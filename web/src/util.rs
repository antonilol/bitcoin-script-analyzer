use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console, js_name = log)]
    pub fn log_empty();

    #[wasm_bindgen(js_namespace = console)]
    pub fn log(s: &str);
}

#[macro_export]
macro_rules! println {
    () => ($crate::util::log_empty());
    ($($t:tt)*) => ($crate::util::log(&format_args!($($t)*).to_string()));
}
