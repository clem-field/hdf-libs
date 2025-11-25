import { describe, it, expect } from 'vitest';
import Ajv from 'ajv';
import addFormats from 'ajv-formats';
import execJsonSchema from '../src/schemas/exec-json.json';
import profileJsonSchema from '../src/schemas/profile-json.json';
import execJsonMinSchema from '../src/schemas/exec-jsonmin.json';

describe('JSON Schema Validation', () => {
  const ajv = new Ajv({ strict: false, allErrors: true });
  addFormats(ajv);

  describe('exec-json schema', () => {
    const validate = ajv.compile(execJsonSchema);

    it('should validate a minimal valid exec-json document', () => {
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
            name: 'test-profile',
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

  describe('profile-json schema', () => {
    const validate = ajv.compile(profileJsonSchema);

    it('should validate a minimal valid profile-json document', () => {
      const validDoc = {
        name: 'test-profile',
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
        name: 'test-profile',
        // missing: supports, controls, groups, sha256
      };

      const isValid = validate(invalidDoc);
      expect(isValid).toBe(false);
      expect(validate.errors).not.toBeNull();
    });
  });

  describe('exec-jsonmin schema', () => {
    const validate = ajv.compile(execJsonMinSchema);

    it('should validate a minimal valid exec-jsonmin document', () => {
      const validDoc = {
        statistics: {
          duration: 0.5,
        },
        controls: [],
        version: '4.18.108',
      };

      const isValid = validate(validDoc);
      expect(isValid).toBe(true);
      expect(validate.errors).toBeNull();
    });

    it('should reject document missing required fields', () => {
      const invalidDoc = {
        version: '4.18.108',
        // missing: statistics, controls
      };

      const isValid = validate(invalidDoc);
      expect(isValid).toBe(false);
      expect(validate.errors).not.toBeNull();
    });
  });
});
