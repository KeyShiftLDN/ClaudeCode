export interface DnsxResult {
    resolved: Array<{
        domain: string;
        ip: string;
        type?: string;
    }>;
    count: number;
    error?: string;
}
export declare function executeDnsx(domains: string[], recordType?: string): Promise<DnsxResult>;
