// Event emitter for cross-component communication
class EventEmitter {
  private events: { [key: string]: Function[] } = {}

  on(event: string, callback: Function) {
    if (!this.events[event]) {
      this.events[event] = []
    }
    this.events[event].push(callback)
  }
  off(event: string, callback: Function) {
    if (this.events[event]) {
      this.events[event] = this.events[event].filter(cb => cb !== callback)
    }
  }

  emit(event: string, data?: any) {
    if (this.events[event]) {
      this.events[event].forEach(callback => callback(data))
    }
  }
}

export const eventBus = new EventEmitter()
