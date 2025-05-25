use std::sync::mpsc::{Sender, channel};
use std::sync::{Arc, Mutex};
use std::thread::Scope;

#[derive(Clone)]
pub struct ThreadPool<'a> {
    sender: Sender<Box<dyn FnOnce() + Send + 'a>>,
}

impl<'a> ThreadPool<'a> {
    pub fn new(scope: &'a Scope<'a, '_>, worker_threads: usize) -> Self {
        let (sender, receiver) = channel::<Box<dyn FnOnce() + Send + 'a>>();
        let receiver = Arc::new(Mutex::new(receiver));
        for _ in 0..worker_threads {
            let receiver = receiver.clone();

            scope.spawn(move || {
                while let Ok(f) = {
                    let guard = receiver.lock().unwrap();
                    let f = guard.recv();
                    drop(guard);
                    f
                } {
                    f();
                }
            });
        }

        Self { sender }
    }

    pub fn submit_job<F: FnOnce() + Send + 'a>(&self, job: F) {
        self.sender.send(Box::new(job)).unwrap();
    }
}
