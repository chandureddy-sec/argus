package agent

import "sync"

// Queue is a bounded, FIFO, in-memory buffer for offline resilience. When it is
// full it drops the OLDEST events (and counts the drops) so a wedged uplink
// cannot exhaust memory and the newest telemetry is preferred.
type Queue struct {
	mu       sync.Mutex
	items    []*Event
	capacity int
	dropped  int
}

// NewQueue builds a queue holding at most capacity events (default 1024).
func NewQueue(capacity int) *Queue {
	if capacity <= 0 {
		capacity = 1024
	}
	return &Queue{capacity: capacity}
}

// Push appends an event, dropping the oldest if that would exceed capacity.
func (q *Queue) Push(e *Event) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.items = append(q.items, e)
	if len(q.items) > q.capacity {
		over := len(q.items) - q.capacity
		q.items = append(q.items[:0], q.items[over:]...) // drop oldest
		q.dropped += over
	}
}

// PushFront re-queues a batch at the head (used to retry a failed send).
func (q *Queue) PushFront(events []*Event) {
	if len(events) == 0 {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.items = append(append([]*Event(nil), events...), q.items...)
	if len(q.items) > q.capacity {
		q.items = q.items[:q.capacity] // keep the oldest-at-front retry data, drop newest overflow
	}
}

// PopBatch removes and returns up to max events in FIFO order.
func (q *Queue) PopBatch(max int) []*Event {
	q.mu.Lock()
	defer q.mu.Unlock()
	if max <= 0 || len(q.items) == 0 {
		return nil
	}
	n := max
	if n > len(q.items) {
		n = len(q.items)
	}
	out := make([]*Event, n)
	copy(out, q.items[:n])
	q.items = append(q.items[:0], q.items[n:]...)
	return out
}

// Dropped returns how many events were dropped due to overflow.
func (q *Queue) Dropped() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.dropped
}

// Len returns the current queued count.
func (q *Queue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.items)
}
