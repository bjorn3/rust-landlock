use crate::{Access, AccessFs, AccessNet};
use std::error::Error;
use std::path::PathBuf;
use std::{fmt, io};

macro_rules! error_source {
    ($self:ident [$($accum:tt)*]) => {
        match $self {
            $($accum)*
        }
    };
    ($self:ident [$($accum:tt)*] #[error(transparent)] $variant:ident($variant_ty:ty), $($rest:tt)*) => {
        error_source!($self [$($accum)* Self::$variant(err) => Error::source(err),] $($rest)*)
    };
    ($self:ident [$($accum:tt)*] #[error(source = None, $($error:tt)+)] $variant:ident($variant_ty:ty), $($rest:tt)*) => {
        error_source!($self [$($accum)* Self::$variant { $source, .. } => None,] $($rest)*)
    };
    ($self:ident [$($accum:tt)*] #[error(source = $source:ident, $($error:tt)+)] $variant:ident($variant_ty:ty), $($rest:tt)*) => {
        error_source!($self [$($accum)* Self::$variant { $source, .. } => Some($source),] $($rest)*)
    };
}

macro_rules! error_enum {
    (
        $(#[$attr:meta])*
        $vis:vis enum $enum_name:ident $(<$($arg:ident $(: $bound:path)?),*>)? {
            $(#[error($($error:tt)+)] $variant:ident($variant_ty:ty),)*
        }
    ) => {
        $(#[$attr])*
        #[derive(Debug)]
        #[non_exhaustive]
        $vis enum $enum_name $(<$($arg $(: $bound)?),*>)? {
            $($variant($variant_ty),)*
        }

        impl $(<$($arg $(: $bound + fmt::Debug)?),*>)? Error for $enum_name $(<$($arg),*>)? {
            fn source(&self) -> Option<&(dyn Error + 'static)> {
                error_source!(self [] $(#[error($($error)*)] $variant($variant_ty),)*)
            }
        }

        impl $(<$($arg $(: $bound)?),*>)? fmt::Display for $enum_name $(<$($arg),*>)?
            where $($variant_ty: fmt::Display,)* {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                match self {
                    $(Self::$variant(err) => fmt::Display::fmt(err, f),)*
                }
            }
        }
    }
}

macro_rules! error_enum_with_into {
    (
        $(#[$attr:meta])*
        $vis:vis enum $enum_name:ident {
            $(#[error($($kind:tt)+)] $variant:ident($variant_ty:ty),)*
        }
    ) => {
        error_enum! {
            $(#[$attr])*
            $vis enum $enum_name {
                $(#[error($($kind)+)] $variant($variant_ty),)*
            }
        }

        $(impl std::convert::From<$variant_ty> for $enum_name {
            fn from(source: $variant_ty) -> Self {
                Self::$variant(source)
            }
        })*
    }
}

error_enum_with_into! {
    /// Maps to all errors that can be returned by a ruleset action.
    pub enum RulesetError {
        #[error(transparent)]
        HandleAccesses(HandleAccessesError),
        #[error(transparent)]
        CreateRuleset(CreateRulesetError),
        #[error(transparent)]
        AddRules(AddRulesError),
        #[error(transparent)]
        RestrictSelf(RestrictSelfError),
    }
}

#[test]
fn ruleset_error_breaking_change() {
    use crate::*;

    // Generics are part of the API and modifying them can lead to a breaking change.
    let _: RulesetError = RulesetError::HandleAccesses(HandleAccessesError::Fs(
        HandleAccessError::Compat(CompatError::Access(AccessError::Empty)),
    ));
}

error_enum! {
    /// Identifies errors when updating the ruleset's handled access-rights.
    pub enum HandleAccessError<T: Access> {
        #[error(transparent)]
        Compat(CompatError<T>),
    }
}

impl<T> std::convert::From<CompatError<T>> for HandleAccessError<T>
where
    T: Access,
{
    fn from(source: CompatError<T>) -> Self {
        HandleAccessError::Compat(source)
    }
}

error_enum! {
    pub enum HandleAccessesError {
        #[error(transparent)]
        Fs(HandleAccessError<AccessFs>),
        #[error(transparent)]
        Net(HandleAccessError<AccessNet>),
    }
}

// Generically implement for all the access implementations rather than for the cases listed in
// HandleAccessesError (with #[from]).
impl<A> From<HandleAccessError<A>> for HandleAccessesError
where
    A: Access,
{
    fn from(error: HandleAccessError<A>) -> Self {
        A::into_handle_accesses_error(error)
    }
}

/// Identifies errors when creating a ruleset.
#[derive(Debug)]
#[non_exhaustive]
pub enum CreateRulesetError {
    /// The `landlock_create_ruleset()` system call failed.
    #[non_exhaustive]
    CreateRulesetCall { source: io::Error },
    /// Missing call to [`RulesetAttr::handle_access()`](crate::RulesetAttr::handle_access).
    MissingHandledAccess,
}

impl Error for CreateRulesetError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            CreateRulesetError::CreateRulesetCall { source, .. } => Some(source),
            CreateRulesetError::MissingHandledAccess { .. } => None,
        }
    }
}

impl fmt::Display for CreateRulesetError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CreateRulesetError::CreateRulesetCall { source } => {
                write!(f, "failed to create a ruleset: {source}",)
            }
            CreateRulesetError::MissingHandledAccess {} => {
                write!(f, "missing handled access")
            }
        }
    }
}

/// Identifies errors when adding a rule to a ruleset.
#[derive(Debug)]
#[non_exhaustive]
pub enum AddRuleError<T>
where
    T: Access,
{
    /// The `landlock_add_rule()` system call failed.
    #[non_exhaustive]
    AddRuleCall {
        source: io::Error,
    },
    /// The rule's access-rights are not all handled by the (requested) ruleset access-rights.
    UnhandledAccess {
        access: T,
        incompatible: T,
    },
    Compat(CompatError<T>),
}

impl<T> Error for AddRuleError<T>
where
    T: Access,
    CompatError<T>: Error,
    Self: fmt::Debug + fmt::Display,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            AddRuleError::AddRuleCall { source, .. } => Some(source),
            AddRuleError::UnhandledAccess { .. } => None,
            AddRuleError::Compat(err) => Error::source(err),
        }
    }
}

impl<T> fmt::Display for AddRuleError<T>
where
    T: Access,
    T: fmt::Debug,
    CompatError<T>: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AddRuleError::AddRuleCall { source } => {
                write!(f, "failed to add a rule: {source}",)
            }
            AddRuleError::UnhandledAccess {
                access: _,
                incompatible,
            } => write!(
                f,
                "access-rights not handled by the ruleset: {incompatible:?}",
            ),
            AddRuleError::Compat(err) => fmt::Display::fmt(err, f),
        }
    }
}

impl<T> std::convert::From<CompatError<T>> for AddRuleError<T>
where
    T: Access,
{
    fn from(source: CompatError<T>) -> Self {
        AddRuleError::Compat { 0: source }
    }
}

// Generically implement for all the access implementations rather than for the cases listed in
// AddRulesError (with #[from]).
impl<A> From<AddRuleError<A>> for AddRulesError
where
    A: Access,
{
    fn from(error: AddRuleError<A>) -> Self {
        A::into_add_rules_error(error)
    }
}

error_enum! {
    /// Identifies errors when adding rules to a ruleset thanks to an iterator returning
    /// Result<Rule, E> items.
    pub enum AddRulesError {
        #[error(transparent)]
        Fs(AddRuleError<AccessFs>),
        #[error(transparent)]
        Net(AddRuleError<AccessNet>),
    }
}

error_enum! {
    pub enum CompatError<T: Access> {
        #[error(transparent)]
        PathBeneath(PathBeneathError),
        #[error(transparent)]
        Access(AccessError<T>),
    }
}

impl<T> std::convert::From<PathBeneathError> for CompatError<T>
where
    T: Access,
{
    fn from(source: PathBeneathError) -> Self {
        CompatError::PathBeneath(source)
    }
}

impl<T> std::convert::From<AccessError<T>> for CompatError<T>
where
    T: Access,
{
    fn from(source: AccessError<T>) -> Self {
        CompatError::Access(source)
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub enum PathBeneathError {
    /// To check that access-rights are consistent with a file descriptor, a call to
    /// [`RulesetCreatedAttr::add_rule()`](crate::RulesetCreatedAttr::add_rule)
    /// looks at the file type with an `fstat()` system call.
    #[non_exhaustive]
    StatCall { source: io::Error },
    /// This error is returned by
    /// [`RulesetCreatedAttr::add_rule()`](crate::RulesetCreatedAttr::add_rule)
    /// if the related PathBeneath object is not set to best-effort,
    /// and if its allowed access-rights contain directory-only ones
    /// whereas the file descriptor doesn't point to a directory.
    DirectoryAccess {
        access: AccessFs,
        incompatible: AccessFs,
    },
}

impl Error for PathBeneathError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            PathBeneathError::StatCall { source, .. } => Some(source),
            PathBeneathError::DirectoryAccess { .. } => None,
        }
    }
}

impl fmt::Display for PathBeneathError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PathBeneathError::StatCall { source } => {
                write!(f, "failed to check file descriptor type: {source}",)
            }
            PathBeneathError::DirectoryAccess {
                access: _,
                incompatible,
            } => write!(
                f,
                "incompatible directory-only access-rights: {incompatible:?}",
            ),
        }
    }
}

#[derive(Debug)]
// Exhaustive enum
pub enum AccessError<T>
where
    T: Access,
{
    /// The access-rights set is empty, which doesn't make sense and would be rejected by the
    /// kernel.
    Empty,
    /// The best-effort approach was (deliberately) disabled and the requested access-rights are
    /// fully incompatible with the running kernel.
    Incompatible { access: T },
    /// The best-effort approach was (deliberately) disabled and the requested access-rights are
    /// partially incompatible with the running kernel.
    PartiallyCompatible { access: T, incompatible: T },
}

impl<T> Error for AccessError<T>
where
    T: Access,
    Self: fmt::Debug + fmt::Display,
{
}

impl<T> fmt::Display for AccessError<T>
where
    T: Access,
    T: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AccessError::Empty {} => write!(f, "empty access-right"),
            AccessError::Incompatible { access } => write!(
                f,
                "fully incompatible access-rights: {access:?}",
                access = access
            ),
            AccessError::PartiallyCompatible {
                access: _,
                incompatible,
            } => write!(
                f,
                "partially incompatible access-rights: {incompatible:?}",
                incompatible = incompatible
            ),
        }
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub enum RestrictSelfError {
    /// The `prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)` system call failed.
    #[non_exhaustive]
    SetNoNewPrivsCall { source: io::Error },
    /// The `landlock_restrict_self() `system call failed.
    #[non_exhaustive]
    RestrictSelfCall { source: io::Error },
}

impl Error for RestrictSelfError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            RestrictSelfError::SetNoNewPrivsCall { source, .. } => Some(source),
            RestrictSelfError::RestrictSelfCall { source, .. } => Some(source),
        }
    }
}

impl fmt::Display for RestrictSelfError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RestrictSelfError::SetNoNewPrivsCall { source } => {
                write!(f, "failed to set no_new_privs: {source}",)
            }
            RestrictSelfError::RestrictSelfCall { source } => {
                write!(f, "failed to restrict the calling thread: {source}",)
            }
        }
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub enum PathFdError {
    /// The `open()` system call failed.
    #[non_exhaustive]
    OpenCall { source: io::Error, path: PathBuf },
}

impl Error for PathFdError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            PathFdError::OpenCall { source, .. } => Some(source),
        }
    }
}

impl fmt::Display for PathFdError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PathFdError::OpenCall { source, path } => {
                write!(
                    f,
                    "failed to open \"{path}\": {source}",
                    path = path.display()
                )
            }
        }
    }
}

#[cfg(test)]
error_enum_with_into! {
    pub(crate) enum TestRulesetError {
        #[error(transparent)]
        Ruleset(RulesetError),
        #[error(transparent)]
        PathFd(PathFdError),
        #[error(transparent)]
        File(std::io::Error),
    }
}
