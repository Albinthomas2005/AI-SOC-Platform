import React from 'react';
import { TrainingPage } from './index';

type BoundaryState = { hasError: boolean };

export class TrainingPageErrorBoundary extends React.Component<
  React.PropsWithChildren,
  BoundaryState
> {
  state: BoundaryState = { hasError: false };

  static getDerivedStateFromError(): BoundaryState {
    return { hasError: true };
  }

  render() {
    if (this.state.hasError) {
      return (
        <div role='alert' className='euiCallOut euiCallOut--danger'>
          <h2>Training could not be displayed</h2>
          <p>Reload the page to try again. If this continues, contact your Dashboard administrator.</p>
        </div>
      );
    }
    return this.props.children;
  }
}

export const TrainingPageApp: React.FC = () => (
  <TrainingPageErrorBoundary>
    <TrainingPage />
  </TrainingPageErrorBoundary>
);
