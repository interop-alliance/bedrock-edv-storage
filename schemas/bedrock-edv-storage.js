/*!
 * Copyright (c) 2018-2026 Digital Bazaar, Inc.
 */
import cidrRegex from 'cidr-regex';

const controller = {
  title: 'controller',
  type: 'string'
};

const id = {
  title: 'id',
  type: 'string'
};

const ipAllowList = {
  type: 'array',
  minItems: 1,
  items: {
    type: 'string',
    // leading and trailing slashes in regex must be removed
    pattern: cidrRegex.v4({exact: true}).toString().slice(1, -1)
  }
};

const meterId = {
  title: 'Meter ID',
  type: 'string'
};

const referenceId = {
  title: 'referenceId',
  type: 'string'
};

const sequence = {
  title: 'sequence',
  type: 'integer',
  minimum: 0,
  maximum: Number.MAX_SAFE_INTEGER - 1
};

/**
 * The stored HMAC reference `{id, type}`, used by the `hmac` fields of
 * @interop/data-integrity-core IEDVConfig and IIndexEntry (distinct from the
 * runtime IHMAC contract in that package's Cipher module).
 */
const hmac = {
  title: 'hmac',
  type: 'object',
  required: ['id', 'type'],
  additionalProperties: false,
  properties: {
    id,
    type: {
      type: 'string'
    }
  }
};

/**
 * Corresponds to @interop/data-integrity-core IEDVConfig interface.
 */
const edvConfig = {
  title: 'EDV Configuration',
  type: 'object',
  required: ['controller', 'sequence', 'keyAgreementKey', 'hmac', 'meterId'],
  additionalProperties: false,
  properties: {
    id,
    controller,
    keyAgreementKey: {
      type: 'object',
      required: ['id', 'type'],
      additionalProperties: false,
      properties: {
        id,
        type: {
          type: 'string'
        }
      }
    },
    ipAllowList,
    hmac,
    meterId, // server-side only
    referenceId,
    sequence
  }
};

/**
 * Corresponds to @interop/data-integrity-core IJWE interface.
 */
const jwe = {
  title: 'JWE with at least one recipient',
  type: 'object',
  required: ['protected', 'recipients', 'iv', 'ciphertext', 'tag'],
  additionalProperties: false,
  properties: {
    protected: {
      type: 'string'
    },
    recipients: {
      type: 'array',
      minItems: 1,
      items: [{
        type: 'object',
        required: ['header', 'encrypted_key'],
        additionalProperties: false,
        properties: {
          header: {
            type: 'object',
            required: ['alg', 'kid'],
            properties: {
              alg: {
                type: 'string'
              },
              kid: {
                type: 'string'
              },
              epk: {
                type: 'object'
              },
              apu: {
                type: 'string'
              },
              apv: {
                type: 'string'
              }
            }
          },
          encrypted_key: {
            type: 'string'
          }
        }
      }]
    },
    iv: {
      type: 'string'
    },
    ciphertext: {
      type: 'string'
    },
    tag: {
      type: 'string'
    }
  }
};

/**
 * Corresponds to @interop/data-integrity-core IIndexEntry interface (the
 * `attributes` items correspond to IIndexAttribute).
 */
const indexedEntry = {
  title: 'EDV Indexed Entry',
  type: 'object',
  required: ['hmac', 'sequence', 'attributes'],
  additionalProperties: false,
  properties: {
    hmac,
    sequence,
    attributes: {
      type: 'array',
      items: [{
        type: 'object',
        required: ['name', 'value'],
        additionalProperties: false,
        properties: {
          name: {
            type: 'string'
          },
          value: {
            type: 'string'
          },
          unique: {
            type: 'boolean'
          }
        }
      }]
    }
  }
};

/**
 * Corresponds to @interop/data-integrity-core IEncryptedDocument interface (the
 * encrypted, server-stored form -- not the decrypted IEDVDocument).
 */
const edvDocument = {
  title: 'EDV Document',
  type: 'object',
  required: ['id', 'sequence', 'jwe'],
  additionalProperties: false,
  properties: {
    id,
    sequence,
    indexed: {
      type: 'array',
      items: [indexedEntry]
    },
    jwe,
    // Note: `pending` is intentionally absent here. The client (edv-client
    // `_encrypt`) rewrites the cleartext `stream` to `{sequence, chunks}`
    // before sending, so the server envelope never carries `pending` -- it is
    // set only inside the encrypted JWE payload and on the client's local copy.
    // On the first write of a streamed doc this yields `stream: {}`, which is
    // valid here. See @interop/data-integrity-core IEDVDocumentStream.
    stream: {
      type: 'object',
      additionalProperties: false,
      properties: {
        sequence: {
          type: 'integer',
          minimum: 0
        },
        chunks: {
          type: 'integer',
          minimum: 1
        }
      }
    }
  }
};

/**
 * Corresponds to @interop/data-integrity-core IEDVChunk interface.
 */
const edvDocumentChunk = {
  title: 'EDV Document Chunk',
  type: 'object',
  required: ['index', 'jwe', 'offset', 'sequence'],
  additionalProperties: false,
  properties: {
    index: {
      type: 'integer',
      minimum: 0
    },
    jwe,
    offset: {
      type: 'integer',
      minimum: 0
    },
    sequence
  }
};

/**
 * Corresponds to @interop/data-integrity-core IEDVQuery interface.
 */
const edvDocumentQuery = {
  title: 'EDV Document Query',
  type: 'object',
  required: ['index'],
  anyOf: [
    {required: ['equals']},
    {required: ['has']}
  ],
  additionalProperties: false,
  properties: {
    index: {
      type: 'string'
    },
    count: {
      title: 'EDV Query Count',
      type: 'boolean'
    },
    equals: {
      type: 'array',
      minItems: 1,
      items: [{
        type: 'object'
        // items will be `key: value` pairs where values are strings but
        // keys are free-form
      }]
    },
    has: {
      type: 'array',
      minItems: 1,
      items: [{
        type: 'string'
      }]
    },
    returnDocuments: {
      type: 'boolean'
    },
    limit: {
      type: 'integer',
      minimum: 1,
      maximum: 1000
    }
  }
};

/**
 * No @interop/data-integrity-core equivalent; server-side query for listing EDV
 * configs by controller + referenceId.
 */
const getEdvsQuery = {
  title: 'edv query',
  type: 'object',
  required: ['controller', 'referenceId'],
  additionalProperties: false,
  properties: {
    controller,
    referenceId
  }
};

/**
 * Corresponds to @interop/data-integrity-core IDelegatedZcap interface (the
 * `proof` object corresponds to ICapabilityDelegationProof). Assumes
 * Ed25519Signature2020 proofs, so `proof.cryptosuite` is intentionally absent.
 */
const delegatedZcap = {
  title: 'delegatedZcap',
  type: 'object',
  additionalProperties: false,
  required: [
    '@context', 'controller', 'expires', 'id', 'invocationTarget',
    'parentCapability', 'proof'
  ],
  properties: {
    controller,
    id,
    allowedAction: {
      anyOf: [{
        type: 'string'
      }, {
        type: 'array',
        minItems: 1,
        items: {type: 'string'}
      }]
    },
    expires: {
      // FIXME: w3c datetime
      title: 'expires',
      type: 'string'
    },
    '@context': {
      title: '@context',
      anyOf: [{
        type: 'string'
      }, {
        type: 'array',
        minItems: 1,
        items: {type: 'string'}
      }]
    },
    invocationTarget: {
      title: 'Invocation Target',
      type: 'string'
    },
    parentCapability: {
      title: 'Parent Capability',
      type: 'string'
    },
    proof: {
      title: 'Proof',
      type: 'object',
      additionalProperties: false,
      required: [
        'verificationMethod', 'type', 'created', 'proofPurpose',
        'capabilityChain', 'proofValue'
      ],
      properties: {
        verificationMethod: {
          title: 'verificationMethod',
          type: 'string'
        },
        type: {
          title: 'type',
          type: 'string'
        },
        created: {
          title: 'created',
          type: 'string'
        },
        proofPurpose: {
          title: 'proofPurpose',
          type: 'string'
        },
        capabilityChain: {
          title: 'capabilityChain',
          type: 'array',
          minItems: 1,
          items: {
            type: ['string', 'object']
          }
        },
        proofValue: {
          title: 'proofValue',
          type: 'string'
        }
      }
    },
    referenceId
  }
};

// Revocation POST body: same shape as `delegatedZcap`
// (@interop/data-integrity-core IDelegatedZcap).
const postRevocationBody = {...delegatedZcap};

export {
  edvConfig as config,
  edvDocumentChunk as chunk,
  edvDocument as document,
  edvConfig as postConfigBody,
  edvDocumentChunk as postChunkBody,
  edvDocument as postDocumentBody,
  edvDocumentQuery as postDocumentQueryBody,
  getEdvsQuery as getConfigsQuery,
  postRevocationBody
};
