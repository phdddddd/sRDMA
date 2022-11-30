#pragma once

typedef void (*io_cb)(uint32_t id, void* ctx);

 
class IOWatcher {
 public:
  virtual void install_io(int fd, io_cb cb, void* ctx) = 0;
  virtual void stop_io(uint32_t io_id) = 0;
  virtual ~IOWatcher() = default;
};

class GenericWorker {
 public:
  virtual ~GenericWorker() = default;

  // Allocate a block.
  virtual void main_cb() = 0;
  virtual void sometimes_cb() = 0;
  // virtual void install_io(IOWatcher* w) = 0;
  // virtual void set_thread(Thread* t) = 0;
};


class AggregateWorker : public GenericWorker {
  std::vector<GenericWorker*> workers;

 public:
  AggregateWorker() {}

  ~AggregateWorker() {
    for (auto& w : workers) {
      delete w;
    }
  }

  void AddWorker(GenericWorker* w) { workers.push_back(w); }

  void main_cb() {
    for (auto& w : workers) {
      w->main_cb();
    }
  }

  void sometimes_cb() {
    for (auto& w : workers) {
      w->sometimes_cb();
    }
  }
};
