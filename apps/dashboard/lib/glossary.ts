import glossaryData from "./field-glossary.json";

export type GlossaryKey = keyof typeof glossaryData;

export interface GlossaryEntry {
  label?: string;
  title?: string;
  meaning?: string;
  description?: string;
  format?: string;
  example?: string;
}

export function getGlossaryEntry(key: GlossaryKey | string): GlossaryEntry | null {
  if (key in glossaryData) {
    const raw = (glossaryData as Record<string, any>)[key];
    return {
      label: raw.label || raw.title || key,
      title: raw.label || raw.title || key,
      meaning: raw.meaning || raw.description || "",
      description: raw.meaning || raw.description || "",
      format: raw.format || "",
      example: raw.example || "",
    };
  }
  return null;
}

export default glossaryData;
