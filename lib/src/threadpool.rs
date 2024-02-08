#[cfg(feature = "threads")]
use std::{
    sync::{
        mpsc::{channel, Sender},
        Arc, Mutex,
    },
    thread::Scope,
};

#[cfg(feature = "threads")]
#[derive(Clone)]
pub struct ThreadPool<'a> {
    sender: Sender<Box<dyn FnOnce() + Send + 'a>>,
}

#[cfg(feature = "threads")]
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
