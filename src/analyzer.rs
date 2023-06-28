use crate::{
    condition_stack::ConditionStack,
    context::{ScriptContext, ScriptRules, ScriptVersion},
    expr::{Expr, MultisigArgs, OpExprArgs, Opcode1, Opcode2, Opcode3},
    opcode::opcodes,
    script::{
        convert::{decode_bool, decode_int, encode_bool_expr, encode_int_expr},
        stack::Stack,
        ScriptElem, ScriptSlice,
    },
    script_error::ScriptError,
    util::locktime::{
        locktime_to_string, locktime_type_equals, LocktimeType, SEQUENCE_LOCKTIME_MASK,
        SEQUENCE_LOCKTIME_TYPE_FLAG,
    },
};
use core::fmt;

struct LocktimeRequirement {
    exprs: Vec<Expr>,
    req: Option<u32>,
}

impl LocktimeRequirement {
    fn new() -> Self {
        Self {
            exprs: Vec::new(),
            req: None,
        }
    }

    fn locktime_requirement_to_string(&self, relative: bool) -> Option<String> {
        if self.exprs.is_empty() && self.req.is_none() {
            return None;
        }

        let type_ = match self.req.map(|req| LocktimeType::new(req, relative)) {
            Some(LocktimeType::Height) => "height",
            Some(LocktimeType::Time) => "time",
            None => "unknown",
        };

        let tmp;
        let min_value = match self.req {
            Some(req) => {
                tmp = locktime_to_string(req, relative);
                &tmp
            }
            None => "unknown",
        };

        Some(format!(
            "type: {}, minValue: {}{}",
            type_,
            min_value,
            if !self.exprs.is_empty() {
                format!(
                    ", stack elements: {:?}",
                    self.exprs
                        .iter()
                        .map(|s| s.to_string())
                        .collect::<Vec<_>>()
                        .join("\n")
                )
            } else {
                "".to_string()
            }
        ))
    }
}

struct AnalyzerResult {
    stack_size: u32,
    spending_conditions: Vec<Expr>,
    locktime_req: LocktimeRequirement,
    sequence_req: LocktimeRequirement,
}

impl fmt::Display for AnalyzerResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tmp;
        let stack_items_str = if !self.spending_conditions.is_empty() {
            tmp = format!(
                "\n{}",
                self.spending_conditions
                    .iter()
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
                    .join("\n")
            );
            &tmp
        } else {
            " none"
        };

        let locktime = self.locktime_req.locktime_requirement_to_string(false);
        let sequence = self.sequence_req.locktime_requirement_to_string(true);

        let locktime_str = match &locktime {
            Some(s) => s,
            None => "none",
        };
        let sequence_str = match (&sequence, &locktime) {
            (Some(s), _) => s,
            (None, Some(_)) => "non-final (not 0xffffffff)",
            (None, None) => "none",
        };

        write!(
            f,
            "Stack size: {}\n\
            Stack item requirements:\
            {stack_items_str}\n\
            Locktime requirement: {locktime_str}\n\
            Sequence requirement: {sequence_str}",
            self.stack_size,
        )
    }
}

type Results<'a> = Vec<ScriptAnalyzer<'a>>;

#[cfg(feature = "threads")]
type ResultsMut<'a, 'b, 'f> = &'b std::sync::Mutex<Results<'a>>;

#[cfg(not(feature = "threads"))]
type ResultsMut<'a, 'b, 'f> = &'f mut Results<'a>;

#[cfg(feature = "threads")]
type ThreadPool<'a, 'f> = &'f crate::threadpool::ThreadPool<'a>;

#[cfg(not(feature = "threads"))]
type ThreadPool<'a, 'f> = ();

pub fn analyze_script(
    script: ScriptSlice<'_>,
    ctx: ScriptContext,
    worker_threads: usize,
) -> Result<String, String> {
    #[cfg(not(feature = "threads"))]
    assert_eq!(
        worker_threads, 0,
        "Feature \"threads\" disabled, set `worker_threads` to 0 or enable the feature"
    );

    for op in script {
        if let ScriptElem::Op(op) = op {
            if op.is_disabled() {
                return Err(format!(
                    "Script error: {}",
                    ScriptError::SCRIPT_ERR_DISABLED_OPCODE
                ));
            }
        }
    }

    let analyzer = ScriptAnalyzer::from_script(script);

    #[cfg(feature = "threads")]
    let results = {
        let results = std::sync::Mutex::new(Vec::new());

        std::thread::scope(|scope| {
            let pool = crate::threadpool::ThreadPool::new(scope, worker_threads);
            analyzer.analyze(&results, ctx, &pool);
        });

        results.into_inner().unwrap()
    };

    #[cfg(not(feature = "threads"))]
    let results = {
        let mut results = Vec::new();

        analyzer.analyze(&mut results, ctx, ());

        results
    };

    // TODO does not run on multiple threads yet
    let results: Vec<_> = results
        .into_iter()
        .filter_map(|mut a| {
            a.calculate_locktime_requirements()
                .ok()
                .map(|(locktime_req, sequence_req)| AnalyzerResult {
                    locktime_req,
                    sequence_req,
                    stack_size: a.stack.items_used(),
                    spending_conditions: a.spending_conditions,
                })
        })
        .collect();

    if results.is_empty() {
        return Err("Script is unspendable".to_string());
    }

    Ok(format!(
        "Spending paths:\n\n{}",
        results
            .into_iter()
            .map(|res| res.to_string())
            .collect::<Vec<_>>()
            .join("\n\n")
    ))
}

#[derive(Clone)]
pub struct ScriptAnalyzer<'a> {
    stack: Stack,
    altstack: Vec<Expr>,
    spending_conditions: Vec<Expr>,
    script: ScriptSlice<'a>,
    script_offset: usize,
    cs: ConditionStack,
}

impl<'a> ScriptAnalyzer<'a> {
    fn from_script(script: ScriptSlice<'a>) -> Self {
        Self {
            stack: Stack::new(),
            altstack: Vec::new(),
            spending_conditions: Vec::new(),
            script,
            script_offset: 0,
            cs: ConditionStack::new(),
        }
    }

    fn calculate_locktime_requirements(
        &mut self,
    ) -> Result<(LocktimeRequirement, LocktimeRequirement), ScriptError> {
        let mut locktime_requirement = LocktimeRequirement::new();
        let mut sequence_requirement = LocktimeRequirement::new();

        let mut i = 0;
        while i < self.spending_conditions.len() {
            let expr = &self.spending_conditions[i];
            if let Expr::Op(expr) = expr {
                if let OpExprArgs::Args1(op, arg) = &expr.args {
                    let arg = &arg[0];

                    if matches!(
                        op,
                        Opcode1::OP_CHECKLOCKTIMEVERIFY | Opcode1::OP_CHECKSEQUENCEVERIFY
                    ) {
                        let relative = expr.opcode() == opcodes::OP_CHECKSEQUENCEVERIFY;
                        let r = if relative {
                            &mut sequence_requirement
                        } else {
                            &mut locktime_requirement
                        };
                        if let Expr::Bytes(arg) = arg {
                            let min_value = decode_int(arg, 5)?;
                            if min_value < 0 {
                                return Err(ScriptError::SCRIPT_ERR_NEGATIVE_LOCKTIME);
                            } else if !relative && min_value > u32::MAX as i64 {
                                return Err(ScriptError::SCRIPT_ERR_UNSATISFIED_LOCKTIME);
                            }
                            let mut min_value = min_value as u32;
                            if relative {
                                min_value &= SEQUENCE_LOCKTIME_TYPE_FLAG | SEQUENCE_LOCKTIME_MASK;
                            }
                            if let Some(ref mut req) = r.req {
                                if !locktime_type_equals(*req, min_value, relative) {
                                    return Err(ScriptError::SCRIPT_ERR_UNSATISFIED_LOCKTIME);
                                }
                                if *req < min_value {
                                    *req = min_value;
                                }
                            } else {
                                r.req = Some(min_value);
                            }
                        } else {
                            r.exprs.push(arg.clone());
                        }

                        self.spending_conditions.remove(i);
                        continue;
                    }
                }
            }

            i += 1;
        }

        Ok((locktime_requirement, sequence_requirement))
    }

    fn eval_conditions(&mut self, ctx: ScriptContext) -> Result<(), ScriptError> {
        let exprs = &mut self.spending_conditions;
        'i: loop {
            Expr::sort_recursive(exprs);
            let mut j = 0;
            'j: while j < exprs.len() {
                let expr1 = &exprs[j];
                if let Expr::Bytes(bytes) = expr1 {
                    if decode_bool(bytes) {
                        // TODO swap_remove is O(1) but then exprs is not sorted anymore
                        exprs.remove(j);
                        continue 'j;
                    } else {
                        // TODO expr1.error
                        return Err(ScriptError::SCRIPT_ERR_UNKNOWN_ERROR);
                    }
                } else if let Expr::Op(op) = expr1 {
                    if let OpExprArgs::Args2(Opcode2::OP_BOOLAND, args) = &op.args {
                        // TODO no clone needed here
                        let args = args.clone();
                        exprs.remove(j);
                        exprs.extend(args.into_iter());
                        continue 'i;
                    }
                }
                let mut k = 0;
                'k: while k < exprs.len() {
                    if j == k {
                        k += 1;
                        continue 'k;
                    }
                    let expr2 = &exprs[k];
                    if expr1 == expr2 {
                        // (a && a) == a
                        exprs.remove(k);
                        continue 'i;
                    }
                    if let Expr::Op(op) = expr1 {
                        // have to write multiple nested if blocks for now https://github.com/rust-lang/rust/issues/53667
                        if let OpExprArgs::Args1(op, args) = &op.args {
                            if *op == Opcode1::OP_NOT || *op == Opcode1::OP_INTERNAL_NOT {
                                if &args[0] == expr2 {
                                    // (a && !a) == 0

                                    // TODO expr{1,2}.error
                                    return Err(ScriptError::SCRIPT_ERR_UNKNOWN_ERROR);
                                }

                                if let Expr::Op(expr_args_0) = &args[0] {
                                    if expr_args_0.opcode().returns_boolean() {
                                        // (!a && f(a)) -> f(false)

                                        let mut res = expr2.clone();
                                        if res.replace_all(&args[0], &encode_bool_expr(false)) {
                                            exprs[k] = res;
                                            continue 'i;
                                        }
                                    }
                                }
                            }
                        }
                        if let OpExprArgs::Args2(Opcode2::OP_EQUAL, args) = &op.args {
                            // (a == b && f(a)) -> f(b)

                            let mut res = expr2.clone();
                            if res.replace_all(&args[0], &args[1]) {
                                exprs[k] = res;
                                continue 'i;
                            }
                        }
                        if op.opcode().returns_boolean() {
                            // (a && f(a)) -> f(true)

                            let mut res = expr2.clone();
                            if res.replace_all(expr1, &encode_bool_expr(true)) {
                                exprs[k] = res;
                                continue 'i;
                            }
                        }
                    }

                    k += 1;
                }

                if exprs[j].eval(ctx)? {
                    continue 'i; // 'j
                }

                j += 1;
            }

            break Ok(());
        }
    }

    fn analyze<'b>(
        mut self,
        results: ResultsMut<'a, 'b, '_>,
        ctx: ScriptContext,
        pool: ThreadPool<'b, '_>,
    ) {
        if self.analyze_path(results, ctx, pool).is_err() {
            return;
        }

        if self.eval_conditions(ctx).is_err() {
            return;
        }

        #[cfg(feature = "threads")]
        let mut results = results.lock().unwrap();

        results.push(self);
    }

    fn analyze_path<'b>(
        &mut self,
        results: ResultsMut<'a, 'b, '_>,
        ctx: ScriptContext,
        pool: ThreadPool<'b, '_>,
    ) -> Result<(), ScriptError> {
        while self.script_offset < self.script.len() {
            let f_exec = self.cs.all_true();
            let op = self.script[self.script_offset];
            self.script_offset += 1;

            if !f_exec {
                match op {
                    ScriptElem::Bytes(_) => {
                        continue;
                    }
                    ScriptElem::Op(opcode) => {
                        if opcode < opcodes::OP_IF || opcode > opcodes::OP_ENDIF {
                            continue;
                        }
                    }
                }
            }

            match op {
                ScriptElem::Bytes(b) => self.stack.push(Expr::bytes(b)),
                ScriptElem::Op(op) => match op {
                    opcodes::OP_0 => self.stack.push(Expr::bytes(&[])),

                    opcodes::OP_1NEGATE => self.stack.push(Expr::bytes(&[0x81])),

                    opcodes::OP_1
                    | opcodes::OP_2
                    | opcodes::OP_3
                    | opcodes::OP_4
                    | opcodes::OP_5
                    | opcodes::OP_6
                    | opcodes::OP_7
                    | opcodes::OP_8
                    | opcodes::OP_9
                    | opcodes::OP_10
                    | opcodes::OP_11
                    | opcodes::OP_12
                    | opcodes::OP_13
                    | opcodes::OP_14
                    | opcodes::OP_15
                    | opcodes::OP_16 => self.stack.push(Expr::bytes(&[op.opcode - 0x50])),

                    opcodes::OP_NOP => {}

                    opcodes::OP_IF | opcodes::OP_NOTIF => {
                        if f_exec {
                            let minimal_if = ctx.version == ScriptVersion::SegwitV1
                                || (ctx.version == ScriptVersion::SegwitV0
                                    && ctx.rules == ScriptRules::All);
                            let [elem] = self.stack.pop();
                            let mut fork = self.clone();
                            self.cs.push_back(op == opcodes::OP_IF);
                            fork.cs.push_back(op != opcodes::OP_IF);
                            if minimal_if {
                                let error = if ctx.version == ScriptVersion::SegwitV1 {
                                    ScriptError::SCRIPT_ERR_TAPSCRIPT_MINIMALIF
                                } else {
                                    ScriptError::SCRIPT_ERR_MINIMALIF
                                };
                                self.spending_conditions
                                    .push(Opcode2::OP_EQUAL.expr_with_error(
                                        Box::new([elem.clone(), encode_bool_expr(true)]),
                                        error,
                                    ));
                                fork.spending_conditions
                                    .push(Opcode2::OP_EQUAL.expr_with_error(
                                        Box::new([elem, encode_bool_expr(false)]),
                                        error,
                                    ));
                            } else {
                                self.spending_conditions.push(elem.clone());
                                fork.spending_conditions
                                    .push(Opcode1::OP_INTERNAL_NOT.expr(Box::new([elem])));
                            }

                            #[cfg(feature = "threads")]
                            {
                                let pool_ = pool.clone();
                                pool.submit_job(move || {
                                    fork.analyze(results, ctx, &pool_);
                                });
                            }

                            #[cfg(not(feature = "threads"))]
                            fork.analyze(results, ctx, pool);
                        } else {
                            self.cs.push_back(false);
                        }
                    }

                    opcodes::OP_ELSE => {
                        if self.cs.empty() {
                            return Err(ScriptError::SCRIPT_ERR_UNBALANCED_CONDITIONAL);
                        }
                        self.cs.toggle_top();
                    }

                    opcodes::OP_ENDIF => {
                        if self.cs.empty() {
                            return Err(ScriptError::SCRIPT_ERR_UNBALANCED_CONDITIONAL);
                        }
                        self.cs.pop_back();
                    }

                    opcodes::OP_VERIFY => {
                        self.verify(ScriptError::SCRIPT_ERR_VERIFY)?;
                    }

                    opcodes::OP_RETURN => {
                        return Err(ScriptError::SCRIPT_ERR_OP_RETURN);
                    }

                    opcodes::OP_TOALTSTACK => {
                        let [elem] = self.stack.pop();
                        self.altstack.push(elem);
                    }

                    opcodes::OP_FROMALTSTACK => {
                        self.stack.push(
                            self.altstack
                                .pop()
                                .ok_or(ScriptError::SCRIPT_ERR_INVALID_ALTSTACK_OPERATION)?,
                        );
                    }

                    opcodes::OP_2DROP => {
                        self.stack.pop::<2>();
                    }

                    opcodes::OP_2DUP => {
                        self.stack.extend_from_within_back(2, 0);
                    }

                    opcodes::OP_3DUP => {
                        self.stack.extend_from_within_back(3, 0);
                    }

                    opcodes::OP_2OVER => {
                        self.stack.extend_from_within_back(2, 2);
                    }

                    opcodes::OP_2ROT => {
                        self.stack.swap_back(0, 2);
                        self.stack.swap_back(1, 3);
                        self.stack.swap_back(2, 4);
                        self.stack.swap_back(3, 5);
                    }

                    opcodes::OP_2SWAP => {
                        self.stack.swap_back(0, 2);
                        self.stack.swap_back(1, 3);
                    }

                    opcodes::OP_IFDUP => {
                        let elem = self.stack.get_back(0).clone();

                        let mut fork = self.clone();
                        fork.spending_conditions
                            .push(Opcode1::OP_INTERNAL_NOT.expr(Box::new([elem.clone()])));

                        #[cfg(feature = "threads")]
                        {
                            let pool_ = pool.clone();
                            pool.submit_job(move || {
                                fork.analyze(results, ctx, &pool_);
                            });
                        }

                        #[cfg(not(feature = "threads"))]
                        fork.analyze(results, ctx, pool);

                        self.spending_conditions.push(elem.clone());
                        self.stack.push(elem);
                    }

                    opcodes::OP_DEPTH => {
                        self.stack.push(encode_int_expr(self.stack.len() as i64));
                    }

                    opcodes::OP_DROP => {
                        self.stack.pop::<1>();
                    }

                    opcodes::OP_DUP => {
                        self.stack.extend_from_within_back(1, 0);
                    }

                    opcodes::OP_NIP => {
                        self.stack.remove_back(1);
                    }

                    opcodes::OP_OVER => {
                        self.stack.extend_from_within_back(1, 1);
                    }

                    opcodes::OP_PICK | opcodes::OP_ROLL => {
                        let index = self.num_from_stack()?;
                        if index < 0 {
                            return Err(ScriptError::SCRIPT_ERR_INVALID_STACK_OPERATION);
                        }
                        let index = index as usize;
                        let elem = match op {
                            opcodes::OP_PICK => self.stack.get_back(index).clone(),
                            opcodes::OP_ROLL => self.stack.remove_back(index),
                            _ => unreachable!(),
                        };
                        self.stack.push(elem);
                    }

                    opcodes::OP_ROT => {
                        self.stack.swap_back(2, 1);
                        self.stack.swap_back(1, 0);
                    }

                    opcodes::OP_SWAP => {
                        self.stack.swap_back(0, 1);
                    }

                    opcodes::OP_TUCK => {
                        self.stack.swap_back(0, 1);
                        self.stack.extend_from_within_back(1, 1);
                    }

                    opcodes::OP_SIZE => {
                        let size = match self.stack.get_back(0) {
                            Expr::Bytes(b) => encode_int_expr(b.len() as i64),
                            elem => Opcode1::OP_SIZE.expr(Box::new([elem.clone()])),
                        };

                        self.stack.push(size);
                    }

                    opcodes::OP_EQUAL | opcodes::OP_EQUALVERIFY => {
                        let elems = self.stack.pop::<2>();
                        self.stack.push(Opcode2::OP_EQUAL.expr(Box::new(elems)));
                        if op == opcodes::OP_EQUALVERIFY {
                            self.verify(ScriptError::SCRIPT_ERR_EQUALVERIFY)?;
                        }
                    }

                    opcodes::OP_1ADD | opcodes::OP_1SUB => {
                        let [elem] = self.stack.pop();
                        self.stack.push(
                            match op {
                                opcodes::OP_1ADD => Opcode2::OP_ADD,
                                opcodes::OP_1SUB => Opcode2::OP_SUB,
                                _ => unreachable!(),
                            }
                            .expr(Box::new([elem, Expr::bytes(&[1])])),
                        );
                    }

                    opcodes::OP_NEGATE => {
                        let [elem] = self.stack.pop();
                        self.stack
                            .push(Opcode2::OP_SUB.expr(Box::new([Expr::bytes(&[]), elem])));
                    }

                    opcodes::OP_ABS | opcodes::OP_NOT | opcodes::OP_0NOTEQUAL => {
                        let [elem] = self.stack.pop();
                        self.stack.push(
                            match op {
                                opcodes::OP_ABS => Opcode1::OP_ABS,
                                opcodes::OP_NOT => Opcode1::OP_NOT,
                                opcodes::OP_0NOTEQUAL => Opcode1::OP_0NOTEQUAL,
                                _ => unreachable!(),
                            }
                            .expr(Box::new([elem])),
                        );
                    }

                    opcodes::OP_ADD
                    | opcodes::OP_SUB
                    | opcodes::OP_BOOLAND
                    | opcodes::OP_BOOLOR
                    | opcodes::OP_NUMEQUAL
                    | opcodes::OP_NUMEQUALVERIFY
                    | opcodes::OP_NUMNOTEQUAL
                    | opcodes::OP_LESSTHAN
                    | opcodes::OP_GREATERTHAN
                    | opcodes::OP_LESSTHANOREQUAL
                    | opcodes::OP_GREATERTHANOREQUAL
                    | opcodes::OP_MIN
                    | opcodes::OP_MAX => {
                        let mut elems = self.stack.pop::<2>();
                        self.stack.push(
                            match op {
                                opcodes::OP_ADD => Opcode2::OP_ADD,
                                opcodes::OP_SUB => Opcode2::OP_SUB,
                                opcodes::OP_BOOLAND => Opcode2::OP_BOOLAND,
                                opcodes::OP_BOOLOR => Opcode2::OP_BOOLOR,
                                opcodes::OP_NUMEQUAL | opcodes::OP_NUMEQUALVERIFY => {
                                    Opcode2::OP_NUMEQUAL
                                }
                                opcodes::OP_NUMNOTEQUAL => Opcode2::OP_NUMNOTEQUAL,
                                opcodes::OP_LESSTHAN => Opcode2::OP_LESSTHAN,
                                opcodes::OP_GREATERTHAN => {
                                    elems.swap(0, 1);
                                    Opcode2::OP_LESSTHAN
                                }
                                opcodes::OP_LESSTHANOREQUAL => Opcode2::OP_LESSTHANOREQUAL,
                                opcodes::OP_GREATERTHANOREQUAL => {
                                    elems.swap(0, 1);
                                    Opcode2::OP_LESSTHANOREQUAL
                                }
                                opcodes::OP_MIN => Opcode2::OP_MIN,
                                opcodes::OP_MAX => Opcode2::OP_MAX,
                                _ => unreachable!(),
                            }
                            .expr(Box::new(elems)),
                        );
                        if op == opcodes::OP_NUMEQUALVERIFY {
                            self.verify(ScriptError::SCRIPT_ERR_NUMEQUALVERIFY)?;
                        }
                    }

                    opcodes::OP_WITHIN => {
                        let elems = self.stack.pop::<3>();
                        self.stack.push(Opcode3::OP_WITHIN.expr(Box::new(elems)));
                    }

                    opcodes::OP_RIPEMD160 | opcodes::OP_SHA1 | opcodes::OP_SHA256 => {
                        let [elem] = self.stack.pop();
                        self.stack.push(
                            match op {
                                opcodes::OP_RIPEMD160 => Opcode1::OP_RIPEMD160,
                                opcodes::OP_SHA1 => Opcode1::OP_SHA1,
                                opcodes::OP_SHA256 => Opcode1::OP_SHA256,
                                _ => unreachable!(),
                            }
                            .expr(Box::new([elem])),
                        );
                    }

                    opcodes::OP_HASH160 | opcodes::OP_HASH256 => {
                        let [elem] = self.stack.pop();
                        self.stack.push(
                            match op {
                                opcodes::OP_HASH160 => Opcode1::OP_RIPEMD160,
                                opcodes::OP_HASH256 => Opcode1::OP_SHA256,
                                _ => unreachable!(),
                            }
                            .expr(Box::new([Opcode1::OP_SHA256.expr(Box::new([elem]))])),
                        );
                    }

                    opcodes::OP_CODESEPARATOR => {}

                    opcodes::OP_CHECKSIG | opcodes::OP_CHECKSIGVERIFY => {
                        let elems = self.stack.pop::<2>();
                        self.stack.push(Opcode2::OP_CHECKSIG.expr(Box::new(elems)));
                        if op == opcodes::OP_CHECKSIGVERIFY {
                            self.verify(ScriptError::SCRIPT_ERR_CHECKSIGVERIFY)?;
                        }
                    }

                    opcodes::OP_CHECKMULTISIG | opcodes::OP_CHECKMULTISIGVERIFY => {
                        if ctx.version == ScriptVersion::SegwitV1 {
                            return Err(ScriptError::SCRIPT_ERR_TAPSCRIPT_CHECKMULTISIG);
                        }

                        let kcount = self.num_from_stack()?;
                        if !(0..=20).contains(&kcount) {
                            return Err(ScriptError::SCRIPT_ERR_PUBKEY_COUNT);
                        }

                        // TODO save some allocations

                        let pks = self.stack.pop_to_box(kcount as usize);

                        let scount = self.num_from_stack()?;
                        if !(0..=kcount).contains(&scount) {
                            return Err(ScriptError::SCRIPT_ERR_SIG_COUNT);
                        }

                        let kcount = kcount as usize;
                        let scount = scount as usize;

                        let sigs = self.stack.pop_to_box(scount);

                        let [dummy] = self.stack.pop();

                        if ctx.rules == ScriptRules::All {
                            self.spending_conditions
                                .push(Opcode2::OP_EQUAL.expr_with_error(
                                    Box::new([dummy, Expr::bytes_owned(Box::new([]))]),
                                    ScriptError::SCRIPT_ERR_SIG_NULLDUMMY,
                                ));
                        }

                        let mut args = Vec::with_capacity(scount + kcount);
                        args.extend(sigs.into_vec());
                        args.extend(pks.into_vec());

                        self.stack
                            .push(MultisigArgs::expr(args.into_boxed_slice(), scount));

                        if op == opcodes::OP_CHECKMULTISIGVERIFY {
                            self.verify(ScriptError::SCRIPT_ERR_CHECKMULTISIGVERIFY)?;
                        }
                    }

                    opcodes::OP_CHECKLOCKTIMEVERIFY | opcodes::OP_CHECKSEQUENCEVERIFY => {
                        let elem = self.stack.get_back(0).clone();
                        self.spending_conditions.push(
                            match op {
                                opcodes::OP_CHECKLOCKTIMEVERIFY => Opcode1::OP_CHECKLOCKTIMEVERIFY,
                                opcodes::OP_CHECKSEQUENCEVERIFY => Opcode1::OP_CHECKSEQUENCEVERIFY,
                                _ => unreachable!(),
                            }
                            .expr(Box::new([elem])),
                        );
                    }

                    opcodes::OP_NOP1
                    | opcodes::OP_NOP4
                    | opcodes::OP_NOP5
                    | opcodes::OP_NOP6
                    | opcodes::OP_NOP7
                    | opcodes::OP_NOP8
                    | opcodes::OP_NOP9
                    | opcodes::OP_NOP10 => {}

                    opcodes::OP_CHECKSIGADD => {
                        if ctx.version != ScriptVersion::SegwitV1 {
                            return Err(ScriptError::SCRIPT_ERR_BAD_OPCODE);
                        }
                        let [sig, n, pk] = self.stack.pop();
                        self.stack.push(Opcode2::OP_ADD.expr(Box::new([
                            n,
                            Opcode2::OP_CHECKSIG.expr(Box::new([sig, pk])),
                        ])));
                    }

                    _ => {
                        return Err(ScriptError::SCRIPT_ERR_BAD_OPCODE);
                    }
                },
            }

            if self.stack.len() + self.altstack.len() > 1000 {
                return Err(ScriptError::SCRIPT_ERR_STACK_SIZE);
            }
        }

        if !self.cs.empty() {
            return Err(ScriptError::SCRIPT_ERR_UNBALANCED_CONDITIONAL);
        }

        if self.stack.len() > 1
            && !(ctx.version == ScriptVersion::Legacy && ctx.rules == ScriptRules::ConsensusOnly)
        {
            return Err(ScriptError::SCRIPT_ERR_CLEANSTACK);
        }

        self.verify(ScriptError::SCRIPT_ERR_EVAL_FALSE)?;

        Ok(())
    }

    fn verify(&mut self, error: ScriptError) -> Result<(), ScriptError> {
        let [elem] = self.stack.pop();
        if let Expr::Bytes(elem) = elem {
            if !decode_bool(&elem) {
                return Err(error);
            }
        } else {
            // TODO insert error?
            self.spending_conditions.push(elem);
        }
        Ok(())
    }

    fn num_from_stack(&mut self) -> Result<i64, ScriptError> {
        if let [Expr::Bytes(top)] = self.stack.pop() {
            decode_int(&top, 4)
        } else {
            Err(ScriptError::SCRIPT_ERR_UNKNOWN_DEPTH)
        }
    }
}
