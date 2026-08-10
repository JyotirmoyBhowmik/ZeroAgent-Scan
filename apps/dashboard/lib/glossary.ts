import glossaryData from "./field-glossary.json";

export type GlossaryKey = keyof typeof glossaryData;

export interface GlossaryEntry {
  title: string;
  description: string;
  format: string;
  example: string;
}

export function getGlossaryEntry(key: GlossaryKey | string): GlossaryEntry | null {
  if (key in glossaryData) {
    return (glossaryData as Record<string, GlossaryEntry>)[key];
  }
  return null;
}

export default glossaryData;
