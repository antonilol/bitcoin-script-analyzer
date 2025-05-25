use bitcoin_script_analyzer::util::{decode_hex_in_place_ignore_whitespace, encode_hex_easy};
use bitcoin_script_analyzer::{
    OwnedScript, ScriptContext, ScriptRules, ScriptVersion, analyze_script,
};
use std::{cell::RefCell, rc::Rc};
use wasm_bindgen::prelude::*;
use web_sys::{Document, Event, HtmlElement, HtmlInputElement, HtmlSelectElement};

mod util;

macro_rules! html_element_or {
    () => {
        HtmlElement
    };
    ($ty:ty) => {
        $ty
    };
}

macro_rules! html_elements {
    ($($name:ident $(: $ty:ty)? = $id:literal,)*) => {
        #[allow(dead_code)]
        #[derive(Clone)]
        struct HtmlElements {
            $(
                $name: html_element_or!($($ty)?),
            )*
        }

        impl HtmlElements {
            fn get(document: &Document) -> Self {
                Self {
                    $(
                        $name: document.get_element_by_id($id).unwrap().dyn_into().unwrap(),
                    )*
                }
            }
        }
    };
}

html_elements! {
    asm = "asm",
    asm_error = "asm-error",
    hex = "hex",
    hex_error = "hex-error",
    analysis = "analysis",
    script_version: HtmlSelectElement = "script-version",
    script_rules: HtmlSelectElement = "script-rules",
    chain_import: HtmlInputElement = "chain-import",
    chain_import_button = "chain-import-button",
    chain_import_error = "chain-import-error",
    chain_import_url: HtmlInputElement = "chain-import-url",
}

impl HtmlElements {
    fn get_script_version(&self) -> ScriptVersion {
        match self.script_version.selected_index() {
            0 => ScriptVersion::Legacy,
            1 => ScriptVersion::SegwitV0,
            _ => ScriptVersion::SegwitV1,
        }
    }

    fn get_script_rules(&self) -> ScriptRules {
        match self.script_rules.selected_index() {
            0 => ScriptRules::All,
            _ => ScriptRules::ConsensusOnly,
        }
    }

    fn get_script_context(&self) -> ScriptContext {
        ScriptContext::new(self.get_script_version(), self.get_script_rules())
    }
}

struct GlobalMutableState {
    script_context: Option<ScriptContext>,
    last_script_bytes: Option<Vec<u8>>,
    // last_asm_inner_text: Option<String>,
    // last_hex_inner_text: Option<String>,
    error: bool,
}

impl GlobalMutableState {
    fn new() -> Self {
        Self {
            script_context: None,
            last_script_bytes: None,
            // last_asm_inner_text: None,
            // last_hex_inner_text: None,
            error: false,
        }
    }
}

struct GlobalState {
    mutable_state: RefCell<GlobalMutableState>,
    elements: HtmlElements,
}

impl GlobalState {
    fn new() -> Self {
        let document = web_sys::window()
            .expect("web_sys::window() returned None")
            .document()
            .expect("Window::document() returned None");

        Self {
            mutable_state: RefCell::new(GlobalMutableState::new()),
            elements: HtmlElements::get(&document),
        }
    }
}

#[wasm_bindgen(start)]
fn main() {
    // #[cfg(debug_assertions)]
    console_error_panic_hook::set_once();

    let global_state = Rc::new(GlobalState::new());

    let options_callback = {
        let global_state = global_state.clone();
        Closure::wrap(Box::new(move |_| {
            let elements = &global_state.elements;

            let ctx = elements.get_script_context();

            let Ok(mut m) = global_state.mutable_state.try_borrow_mut() else {
                println!("BUG: unable to borrow_mut mutable state");
                return;
            };

            if Some(ctx) == m.script_context {
                // no change
                return;
            }

            m.script_context = Some(ctx);

            if m.error {
                // parsing wont be different
                return;
            }

            let s = elements.hex.inner_text();
            let mut hex = s.into_bytes();
            match decode_hex_in_place_ignore_whitespace(&mut hex)
                .map_err(|err| err.to_string())
                .and_then(|bytes| {
                    OwnedScript::parse_from_bytes(bytes).map_err(|err| err.to_string())
                }) {
                Ok(script) => {
                    let res = match analyze_script(&script, ctx, 0) {
                        Ok(res) | Err(res) => res,
                    };

                    elements.hex_error.set_text_content(None);
                    elements.analysis.set_inner_text(&res);

                    // m.error = false;
                }
                Err(err) => {
                    elements.hex_error.set_inner_text(&err);

                    m.error = true;
                }
            }
        }) as Box<dyn Fn(Event)>)
    };

    let hex_input_callback = {
        let global_state = global_state.clone();
        Closure::wrap(Box::new(move |_| {
            let elements = &global_state.elements;

            let Ok(mut m) = global_state.mutable_state.try_borrow_mut() else {
                println!("BUG: unable to borrow_mut mutable state");
                return;
            };

            let s = elements.hex.inner_text();
            let mut hex = s.into_bytes();
            match decode_hex_in_place_ignore_whitespace(&mut hex)
                .map_err(|err| err.to_string())
                .and_then(|bytes| {
                    OwnedScript::parse_from_bytes(bytes).map_err(|err| err.to_string())
                }) {
                Ok(script) => {
                    let res = match analyze_script(
                        &script,
                        *m.script_context
                            .get_or_insert_with(|| elements.get_script_context()),
                        0,
                    ) {
                        Ok(res) | Err(res) => res,
                    };

                    elements.hex_error.set_text_content(None);
                    elements.asm_error.set_text_content(None);
                    elements.asm.set_inner_text(&script.to_string());
                    elements.analysis.set_inner_text(&res);

                    m.error = false;
                }
                Err(err) => {
                    elements.hex_error.set_inner_text(&err);

                    m.error = true;
                }
            }
        }) as Box<dyn Fn(Event)>)
    };

    let asm_input_callback = {
        let global_state = global_state.clone();
        Closure::wrap(Box::new(move |_| {
            let elements = &global_state.elements;

            let Ok(mut m) = global_state.mutable_state.try_borrow_mut() else {
                println!("BUG: unable to borrow_mut mutable state");
                return;
            };

            let asm = elements.asm.inner_text();
            let mut buf = asm.into_bytes();
            match OwnedScript::parse_from_asm_in_place(&mut buf) {
                Ok((bytes, script)) => {
                    if Some(bytes) == m.last_script_bytes.as_deref() {
                        // no change
                        return;
                    }
                    // bytes to hex TODO
                    let res = match analyze_script(
                        &script,
                        *m.script_context
                            .get_or_insert_with(|| elements.get_script_context()),
                        0,
                    ) {
                        Ok(res) | Err(res) => res,
                    };

                    elements.hex_error.set_text_content(None);
                    elements.asm_error.set_text_content(None);
                    elements.hex.set_inner_text(&encode_hex_easy(bytes));
                    elements.analysis.set_inner_text(&res);

                    m.error = false;
                }
                Err(err) => {
                    elements.asm_error.set_inner_text(&err.to_string());

                    m.error = true;
                }
            }
        }) as Box<dyn Fn(Event)>)
    };

    let options_callback_ref = options_callback.as_ref().unchecked_ref();
    let hex_input_callback_ref = hex_input_callback.as_ref().unchecked_ref();
    let asm_input_callback_ref = asm_input_callback.as_ref().unchecked_ref();

    let elements = &global_state.elements;

    elements
        .script_rules
        .add_event_listener_with_callback("change", options_callback_ref)
        .expect("can't add_event_listener");
    elements
        .script_version
        .add_event_listener_with_callback("change", options_callback_ref)
        .expect("can't add_event_listener");

    for ev_type in ["keydown", "keypress", "keyup"] {
        elements
            .asm
            .add_event_listener_with_callback(ev_type, asm_input_callback_ref)
            .expect("can't add_event_listener");
        elements
            .hex
            .add_event_listener_with_callback(ev_type, hex_input_callback_ref)
            .expect("can't add_event_listener");
    }

    options_callback.forget();
    hex_input_callback.forget();
    asm_input_callback.forget();
}

/*
TODO from js

html.chainImportButton.addEventListener('click', async () => {
    const address = html.chainImport.value;
    const apiURL = html.chainImportURL.value;
    let script: Awaited<ReturnType<typeof getScript>>;
    try {
        script = await getScript(apiURL, address);
    } catch (e) {
        html.chainImportError.innerText = e instanceof Error ? e.message : String(e);
        return;
    }
    html.chainImportError.innerText = '';
    html.hex.innerText = script.hex;
    html.scriptVersion.selectedIndex = script.version;
    hexUpdate();
}); */
