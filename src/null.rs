use crate::handlers::PamEventHandler;

#[derive(Debug, Clone, Default)]
pub(crate) struct NullHandler;

impl PamEventHandler for NullHandler {
    fn from_args(_args: &[String]) -> Self
    where
        Self: Sized + Default,
    {
        Self
    }
}
