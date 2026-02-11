import { render, screen } from '@testing-library/react';
import Home from '../page';

describe('QIMEM Playground', () => {
  it('renders core sections', () => {
    render(<Home />);
    expect(screen.getByRole('heading', { name: 'QIMEM Playground' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Dev Access Panel' })).toBeInTheDocument();
    expect(screen.getAllByText('Encryption Lab').length).toBeGreaterThan(0);
  });
});
