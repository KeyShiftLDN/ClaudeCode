export interface SubfinderResult {
    subdomains: string[];
    count: number;
    error?: string;
}
export declare function executeSubfinder(domain: string, silent?: boolean): Promise<SubfinderResult>;
