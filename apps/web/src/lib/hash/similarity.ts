/**
 * Similarity comparison utilities
 * Wrapper functions for SDK similarity methods
 */

import * as sdk from "@ilovehash/sdk";

export interface SimilarityComparisonResult {
  hash1: string;
  hash2: string;
  distance?: number;
  similarity?: number;
  algorithm: string;
}

/**
 * Compare two SimHash values
 */
export function compareSimHash(hash1: string, hash2: string): { distance: number; similarity: number } {
  const distance = sdk.simhashHammingDistance(hash1, hash2);
  const similarity = sdk.simhashSimilarity(hash1, hash2);
  return { distance, similarity };
}

/**
 * Compare two MinHash values (requires signature arrays)
 * Note: MinHash returns signatures, not simple hashes, so we need to parse them
 */
export function compareMinHash(hash1: string, hash2: string): { similarity: number } | null {
  try {
    // MinHash signatures are typically stored as hex-encoded arrays
    // We need to convert hex strings to Uint32Array
    // This is a simplified approach - actual implementation may vary
    const sig1 = parseMinHashSignature(hash1);
    const sig2 = parseMinHashSignature(hash2);
    
    if (sig1 && sig2) {
      const similarity = sdk.minhashJaccard(sig1, sig2);
      return { similarity };
    }
  } catch (error) {
    console.error("Error comparing MinHash:", error);
  }
  return null;
}

/**
 * Compare two Nilsimsa values
 */
export function compareNilsimsa(hash1: string, hash2: string): { distance: number; similarity: number } {
  // Nilsimsa compare returns -128 to 128, where 128 is identical
  const compareResult = sdk.nilsimsaCompare(hash1, hash2);
  // Normalize to 0-1 similarity score
  const similarity = (compareResult + 128) / 256;
  // Distance is inverse of similarity
  const distance = 128 - compareResult;
  return { distance, similarity };
}

/**
 * Parse MinHash signature from hex string
 * This is a helper function - actual format may need adjustment
 */
function parseMinHashSignature(hex: string): Uint32Array | null {
  try {
    // Assuming hex string represents a series of 32-bit integers
    // Each integer is 8 hex characters (4 bytes)
    if (hex.length % 8 !== 0) return null;
    
    const length = hex.length / 8;
    const sig = new Uint32Array(length);
    
    for (let i = 0; i < length; i++) {
      const hexValue = hex.slice(i * 8, (i + 1) * 8);
      sig[i] = parseInt(hexValue, 16);
    }
    
    return sig;
  } catch (error) {
    return null;
  }
}

/**
 * Compare two similarity hashes based on algorithm type
 */
export async function compareSimilarityHashes(
  algorithm: string,
  hash1: string,
  hash2: string
): Promise<{ distance?: number; similarity?: number } | null> {
  switch (algorithm) {
    case "simhash":
      return compareSimHash(hash1, hash2);
    
    case "minhash":
    case "bbitminhash":
    case "superminhash":
      return compareMinHash(hash1, hash2);
    
    case "nilsimsa":
      return compareNilsimsa(hash1, hash2);
    
    case "imatch":
      // I-Match doesn't have a built-in comparison function
      // Could implement Hamming distance or other metric
      return { distance: hammingDistance(hash1, hash2) };
    
    default:
      // Fallback to Hamming distance for unknown algorithms
      return { distance: hammingDistance(hash1, hash2) };
  }
}

/**
 * Simple Hamming distance between two hex strings
 */
function hammingDistance(hex1: string, hex2: string): number {
  if (hex1.length !== hex2.length) return -1;
  
  let distance = 0;
  for (let i = 0; i < hex1.length; i++) {
    const val1 = parseInt(hex1[i] || '0', 16);
    const val2 = parseInt(hex2[i] || '0', 16);
    const xor = val1 ^ val2;
    // Count set bits
    distance += (xor & 1) + ((xor >> 1) & 1) + ((xor >> 2) & 1) + ((xor >> 3) & 1);
  }
  return distance;
}
