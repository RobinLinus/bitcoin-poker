use std::sync::Mutex;

use zeroize::Zeroize;

use crate::{MAX_ERROR_LEN, MAX_OUTPUT_LEN, SECRET_LEN, engine::DealEngine};

pub(crate) static MODULE: Mutex<ModuleState> = Mutex::new(ModuleState::new());

pub(crate) struct ModuleState {
    pub(crate) input: Vec<u8>,
    pub(crate) output: Vec<u8>,
    pub(crate) last_error: Vec<u8>,
    pub(crate) local_secret: [u8; SECRET_LEN],
    pub(crate) supplied_entropy: [u8; SECRET_LEN],
    pub(crate) engine: Option<DealEngine>,
    pub(crate) permanently_cleared: bool,
}

impl ModuleState {
    const fn new() -> Self {
        Self {
            input: Vec::new(),
            output: Vec::new(),
            last_error: Vec::new(),
            local_secret: [0; SECRET_LEN],
            supplied_entropy: [0; SECRET_LEN],
            engine: None,
            permanently_cleared: false,
        }
    }

    pub(crate) fn clear_error(&mut self) {
        self.last_error.clear();
    }

    pub(crate) fn fail(&mut self, code: i32, message: impl AsRef<str>) -> i32 {
        self.last_error.clear();
        self.last_error
            .extend_from_slice(message.as_ref().as_bytes());
        self.last_error.truncate(MAX_ERROR_LEN);
        code
    }

    pub(crate) fn replace_output(&mut self, output: Vec<u8>) -> Result<(), &'static str> {
        self.output.zeroize();
        self.output.clear();
        if output.len() > MAX_OUTPUT_LEN {
            return Err("DEAL output exceeds its fixed Wasm boundary");
        }
        self.output = output;
        Ok(())
    }

    pub(crate) fn clear_staging(&mut self) {
        self.input.zeroize();
        self.input.clear();
        self.local_secret.zeroize();
        self.supplied_entropy.zeroize();
    }
}

pub(crate) fn with_module(operation: impl FnOnce(&mut ModuleState) -> i32) -> i32 {
    match MODULE.lock() {
        Ok(mut state) => operation(&mut state),
        Err(_) => -127,
    }
}

pub(crate) fn with_engine(
    state: &mut ModuleState,
    operation: impl FnOnce(&mut DealEngine) -> Result<Vec<u8>, String>,
) -> i32 {
    state.clear_error();
    let result = match state.engine.as_mut() {
        Some(engine) => operation(engine),
        None => return state.fail(1, "DEAL worker is not initialized"),
    };
    match result {
        Ok(output) => match state.replace_output(output) {
            Ok(()) => 0,
            Err(error) => state.fail(5, error),
        },
        Err(error) => state.fail(4, error),
    }
}
