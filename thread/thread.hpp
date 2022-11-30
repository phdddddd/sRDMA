#pragma once

#include <ev++.h>
#include <atomic>
#include <cassert>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <thread> // c++ use thread for multi threads, while c use pthread, thread make it easier to use
#include <vector>

class Thread;
#include "../worker/generic_worker.hpp"

#define NOW 0.000000001

class Thread : public IOWatcher {
  struct my_io : public ev::io {
    my_io(uint32_t id, io_cb cb, void *ctx) : id(id), cb(cb), ctx(ctx) {
      // empty
    }
    uint32_t id;
    io_cb cb;
    void *ctx;
  };

  // events
  ev::async stopper;      // for termination
  ev::idle main_event;    // main event which is called when is not busy
  ev::timer timer_event;  // call something time to time
  ev::dynamic_loop loop;  // loop of the thread

  //  ev::async notify;         // for notifying about incoming messeges

  const uint32_t _thread_id;

  GenericWorker *_worker;

  std::thread the_thread;

  std::map<uint32_t, my_io *> io_events;
  uint32_t current_io_id;
  float cb_timeout;

 public:
  // cb_timeout is in seconds
  explicit Thread(uint32_t _thread_id, float cb_timeout = 5.0)
      : loop(ev::AUTO),
        _thread_id(_thread_id),
        current_io_id(0),
        cb_timeout(cb_timeout) {
    // empty
  }

  void install_worker(GenericWorker *w) { this->_worker = w; }

  ~Thread() {
    text(log_fp, "\t[Thread] Try to destroy worker(%u)\n", _thread_id);
  
    delete _worker;
    
    text(log_fp, "\t\t[Thread] Worker is destroyed\n");
  }

  void Start() { this->the_thread = std::thread(&Thread::main_method, this); }

  uint32_t GetId() const { return _thread_id; };

  void main_cb(ev::idle &w, int revents) { _worker->main_cb(); }

  void io_process(ev::io &w, int revents) {
    my_io &new_d = static_cast<my_io &>(w);
    new_d.cb(new_d.id, new_d.ctx);
  }

  void install_io(int fd, io_cb cb, void *ctx) override {
    my_io *io = new my_io(current_io_id, cb, ctx);
    io_events[current_io_id] = io;
    current_io_id++;
    io->set(this->loop);
    io->set<Thread, &Thread::io_process>(this);
    io->start(fd, ev::READ);
  }

  void stop_io(uint32_t io_id) override {
    auto it = io_events.find(io_id);
    assert(it != io_events.end());
    delete it->second;
    io_events.erase(it);
  }

  void main_method() {
    // create async stopper for terminating the tread

    this->stopper.set(this->loop);
    this->stopper.set<Thread, &Thread::terminate_cb>(this);
    this->stopper.priority = EV_MAXPRI - 1;
    this->stopper.start();

    this->timer_event.set(this->loop);
    this->timer_event.set<Thread, &Thread::timer_cb>(this);
    this->timer_event.set(cb_timeout, cb_timeout);  // after 10  repeat 50
    this->timer_event.priority = EV_MAXPRI - 1;
    this->timer_event.start(cb_timeout, cb_timeout);  // after 10  repeat 50

    this->main_event.set(this->loop);
    this->main_event.set<Thread, &Thread::main_cb>(this);
    this->main_event.priority = EV_MAXPRI;
    this->main_event.start();

    this->loop.run(0);
  }

  void timer_cb(ev::timer &w, int revents) {
    _worker->sometimes_cb();
    // SCHEDULE_CALLBACK(5, resend_cb, new request_cb_t(item,this));

    w.repeat = cb_timeout;  // repeat after cb_timeout seconds
    w.again();
  }

  void Stop() {
    text(log_fp, "[Thread] Try stopping thread(%d)\n", this->GetId());
    this->stopper.send();
    if (this->the_thread.joinable()) {
      this->the_thread.join();
    }
  }

  void terminate_cb() {
    //  dumb_stats();
    for (auto &pair : io_events) {
      delete pair.second;
    }

    this->stopper.stop();
    this->timer_event.stop();
    this->main_event.stop();

    this->loop.break_loop(ev::ALL);
    text(log_fp, "[Thread] Thread(%d) is terminated\n", this->GetId());
  }

  pthread_t native_handle() { return the_thread.native_handle(); }

 private:
  Thread(const Thread &) = delete;
  void operator=(const Thread &) = delete;
};

class LauncherMaster {
 public:
  LauncherMaster() {
    instance = this;
    std::signal(SIGINT, LauncherMaster::signal_handler);
  }

  ~LauncherMaster() {
    text(log_fp, "[LauncherMaster] Try to destroy all threads\n");

    for (auto &iter : threads) {
      delete iter;
    }
    text(log_fp, "\t[LauncherMaster] All threads are destroyed\n");
  }

  void add_thread(Thread *t) { threads.push_back(t); }

  void launch() {
    for (uint32_t i = 1; i < threads.size(); ++i) {
      text(log_fp, "\t[LauncherMaster] start thread %u\n", i);
      threads[i]->Start();
      text(log_fp, "\t[LauncherMaster] Pin the thread to core %u\n", i);
      cpu_set_t set;
      CPU_ZERO(&set);
      CPU_SET(i, &set);
      pthread_setaffinity_np(this->threads[i]->native_handle(),
                             sizeof(cpu_set_t), &set);
    }
    text(log_fp, "\t[LauncherMaster] start thread 0\n");
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(0, &set);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &set);

    threads[0]->main_method();
  }

 private:
  void handler_wraper(int signum) {
    text(log_fp, "[LauncherMaster] Signal(%d) is  detected \n", signum);

    for (uint32_t i = 0; i < threads.size(); ++i) {
      threads[i]->Stop();
    }
    text(log_fp, "\t[LauncherMaster] All threads are stopped\n");
  }

  std::vector<Thread *> threads;

  static LauncherMaster *instance;

  static void signal_handler(int signum) { instance->handler_wraper(signum); }
};

LauncherMaster *LauncherMaster::instance = nullptr;
