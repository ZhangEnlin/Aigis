import { AigisContentSchema, ImporterSchema } from '../common/schema';
import { AegisImporter } from './aegis';
import { AigisImporter } from './aigis';

const aigisImporter = new AigisImporter();
const aegisImporter = new AegisImporter();
export const ImporterSelections: Map<string, ImporterSchema> = new Map([
    [aigisImporter.schema.type, aigisImporter.schema],
    [aegisImporter.schema.type, aegisImporter.schema],
]);
export const ImporterDescriptions: (ResourceStr|undefined)[] = [
    aigisImporter.schema.description,
    aegisImporter.schema.description,
];

export interface ImporterBehavior {
    schema: ImporterSchema,
    load: (fd: number, password: string) => Promise<AigisContentSchema | undefined>,
    save: (fd: number, masterKeyAlias: string, content: AigisContentSchema) => Promise<boolean>,
}

export function dispatchImporter(type: string): ImporterBehavior | undefined {
    switch (type) {
        case 'aigis':
            return aigisImporter;
        case 'aegis':
            return aegisImporter;
        default:
            return undefined;
    }
}
