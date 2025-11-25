import { describe, it, expect } from 'vitest';
import Ajv from 'ajv';
import addFormats from 'ajv-formats';
import hdfResultsSchema from '../src/schemas/hdf-results.json';
import hdfBaselineSchema from '../src/schemas/hdf-baseline.json';

describe('JSON Schema Validation', () => {
  const ajv = new Ajv({ strict: false, allErrors: true });
  addFormats(ajv);

  describe('hdf-results schema', () => {
    const validate = ajv.compile(hdfResultsSchema);

    it('should validate a minimal valid hdf-results document', () => {
      const validDoc = {
        platform: {
          name: 'ubuntu',
          release: '20.04',
        },
        profiles: [],
        statistics: {
          duration: 0.5,
        },
        version: '4.18.108',
      };

      const isValid = validate(validDoc);
      expect(isValid).toBe(true);
      expect(validate.errors).toBeNull();
    });

    it('should reject document missing required fields', () => {
      const invalidDoc = {
        platform: { name: 'ubuntu', release: '20.04' },
        // missing: profiles, statistics, version
      };

      const isValid = validate(invalidDoc);
      expect(isValid).toBe(false);
      expect(validate.errors).not.toBeNull();
    });

    it('should validate a document with controls and results', () => {
      const docWithControls = {
        platform: { name: 'ubuntu', release: '20.04' },
        profiles: [
          {
            name: 'test-baseline',
            sha256: 'abc123',
            supports: [],
            attributes: [],
            groups: [],
            controls: [
              {
                id: 'V-12345',
                impact: 0.7,
                refs: [],
                tags: { severity: 'high' },
                source_location: { ref: 'controls/test.rb', line: 10 },
                results: [
                  {
                    code_desc: 'File /etc/passwd should exist',
                    start_time: '2025-01-01T00:00:00Z',
                    status: 'passed',
                  },
                ],
              },
            ],
          },
        ],
        statistics: { duration: 1.5 },
        version: '4.18.108',
      };

      const isValid = validate(docWithControls);
      expect(isValid).toBe(true);
      expect(validate.errors).toBeNull();
    });
  });

  describe('hdf-baseline schema', () => {
    const validate = ajv.compile(hdfBaselineSchema);

    it('should validate a minimal valid hdf-baseline document', () => {
      const validDoc = {
        name: 'test-baseline',
        supports: [],
        controls: [],
        groups: [],
        sha256: 'abc123def456',
      };

      const isValid = validate(validDoc);
      expect(isValid).toBe(true);
      expect(validate.errors).toBeNull();
    });

    it('should reject document missing required fields', () => {
      const invalidDoc = {
        name: 'test-baseline',
        // missing: supports, controls, groups, sha256
      };

      const isValid = validate(invalidDoc);
      expect(isValid).toBe(false);
      expect(validate.errors).not.toBeNull();
    });
  });
});
