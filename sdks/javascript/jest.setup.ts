// Jest setup file
import 'jest-environment-jsdom';

// Mock console methods to reduce noise in tests
global.console = {
  ...console,
  warn: jest.fn(),
  error: jest.fn(),
};

// Mock fetch for testing
global.fetch = jest.fn();
