package jobs

import (
	"context"
	"errors"
	"time"

	"k8s.io/klog/v2"
)

// ErrTimeout is returned when Runner's Run method fails due to a timeout event.
var ErrTimeout = errors.New("runner received timeout")

// Runnable is the interface that wraps the basic Run method.
//
// Run should be implemented by any task intended to be executed by the Runner.
type Runnable interface {
	Run(ctx context.Context) error
}

// The RunnableFunc type is an adapter to allow the use of ordinary functions as Runnable tasks.
// If f is a function with the appropriate signature, RunnableFunc(f) is a Runnable that calls f.
type RunnableFunc func(ctx context.Context) error

// Run calls f()
func (f RunnableFunc) Run(ctx context.Context) error {
	return f(ctx)
}

// Runner is the interface that wraps the basic Run method.
//
// Run executes submitted Runnable tasks.
type Runner interface {
	Run(ctx context.Context, task Runnable) error
}

// New constructs a new ready-to-use Runner for running a Runnable task.
func New(opts ...RunnerOption) Runner {
	r := &runner{
		complete:        make(chan error),
		timeoutDuration: 0,
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

type RunnerOption func(*runner)

func WithTimeout(timeout time.Duration) RunnerOption {
	return func(j *runner) {
		j.timeoutDuration = timeout
	}
}

type runner struct {
	// complete channel reports that processing is done
	complete chan error
	// timeout duration
	timeoutDuration time.Duration
}

// Run runs the specified task and monitors channel events.
func (r *runner) Run(ctx context.Context, task Runnable) error {
	go func() {
		r.complete <- task.Run(ctx)
	}()
	if r.timeoutDuration > 0 {
		return r.runWithTimeout(ctx)
	}
	return r.runAndWaitForever()

}

func (r *runner) runAndWaitForever() error {
	return <-r.complete
}

func (r *runner) runWithTimeout(ctx context.Context) error {
	// context timeout also can be set on caller side
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, r.timeoutDuration)
		defer cancel()
	}
	klog.V(3).Infof("Running task with timeout: %v", r.timeoutDuration)
	select {
	// Signaled when processing is done.
	case err := <-r.complete:
		klog.V(3).Infof("Stopping runner on task completion with error: %v", err)
		return err
	// Signaled when we run out of time.
	case <-ctx.Done():
		klog.V(3).Info("Stopping runner on timeout")
		return ErrTimeout
	}
}
