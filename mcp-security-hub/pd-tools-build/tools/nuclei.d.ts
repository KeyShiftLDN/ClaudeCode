export interface NucleiVulnerability {
    template: string;
    templateID: string;
    info: {
        name: string;
        severity: string;
        description?: string;
    };
    matcherName?: string;
    type: string;
    host: string;
    matched?: string;
}
export interface NucleiResult {
    vulnerabilities: NucleiVulnerability[];
    count: number;
    error?: string;
}
export declare function executeNuclei(targets: string[], templates?: string[], severity?: string[]): Promise<NucleiResult>;
