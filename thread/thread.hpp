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
  
  /*
      ev::async stopper;: 一个异步事件处理器，用于线程终止。当发送一个异步通知时，事件循环会立即从 loop.run() 函数中返回。
    ev::idle main_event;: 一个空闲事件处理器，用于在事件循环没有其他事件需要处理时执行某个任务。在本代码中，该处理器会调用 main_cb 函数。
    ev::timer timer_event;: 一个定时器事件处理器，用于在指定时间间隔内调用某个任务。在本代码中，该处理器会定时调用 sometimes_cb 函数。
    ev::dynamic_loop loop;: 线程的事件循环，用于监听和处理上述不同类型的事件。
  */
  
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
    /*注册一个信号处理函数，即在收到信号SIGINT时，执行指定的函数LauncherMaster::signal_handler*/
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
      //将线程绑定到特定的CPU上执行
      cpu_set_t set;
      CPU_ZERO(&set);
      CPU_SET(i, &set);
      /*native_handle()是C++11中用于获取与对象相关联的底层句柄（handle）的函数*/
      /*使用 native_handle()将线程绑定到指定的CPU上，以实现线程的亲和性调度。 */
      pthread_setaffinity_np(this->threads[i]->native_handle(),
                             sizeof(cpu_set_t), &set);
    }
    text(log_fp, "\t[LauncherMaster] start thread 0\n");
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(0, &set);
    /*pthread_self()返回调用线程的线程 ID*/
    /* 此函数可用于获取主线程或使用 POSIX 线程库创建的任何其他线程的线程 ID。 */
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
/*
这个类是一个线程管理器，负责启动和停止多个线程，并在收到 SIGINT 信号时关闭所有线程。下面是每个方法的解释：

    LauncherMaster()：构造函数。它将类实例指针设置为 this，并注册了一个信号处理函数，在收到 SIGINT 信号时执行 signal_handler 函数。
    ~LauncherMaster()：析构函数。在对象销毁时，它删除所有已经添加的线程。
    add_thread(Thread *t)：将一个线程添加到线程管理器中。这个方法会将线程添加到内部的线程列表中，以备后续启动和停止线程时使用。
    launch()：启动线程。这个方法会遍历线程列表，分别启动每个线程，并将其绑定到特定的 CPU 上执行。最后，它会启动主线程并调用 main_method() 函数。
    handler_wraper(int signum)：信号处理函数的包装器。这个函数会停止所有已经添加的线程，当收到 SIGINT 信号时调用。它会在控制台输出一条日志记录所有线程已经停止。
    signal_handler(int signum)：信号处理函数。这个函数是静态函数，并使用类实例的指针调用 handler_wraper() 函数。
    threads：一个线程列表，包含所有已经添加的线程。
    instance：一个静态指针，指向唯一的类实例。由于信号处理函数需要访问非静态成员变量，因此需要一个静态指针来访问类实例。
*/
