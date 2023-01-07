use std::convert::Infallible;
use std::ops::{ControlFlow, FromResidual, Try};

enum Success {
    Yes,
    No,
}

impl From<bool> for Success {
    fn from(value: bool) -> Self {
        if value {
            Success::Yes
        } else {
            Success::No
        }
    }
}

impl FromResidual<<Success as Try>::Residual> for Success {
    fn from_residual(residual: <Success as Try>::Residual) -> Self {
        match residual {
            None => Success::No,
            _ => unreachable!(),
        }
    }
}

impl Try for Success {
    type Output = ();
    type Residual = Option<Infallible>;

    fn from_output(output: Self::Output) -> Self {
        Success::Yes
    }
    fn branch(self) -> ControlFlow<Self::Residual, Self::Output> {
        match self {
            Yes => ControlFlow::Continue(()),
            No => ControlFlow::Break(None),
        }
    }
}
