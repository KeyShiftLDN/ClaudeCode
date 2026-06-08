export interface NaabuResult {
    openPorts: Array<{
        host: string;
        port: number;
    }>;
    count: number;
    error?: string;
}
export declare function executeNaabu(hosts: string[], ports?: string, topPorts?: number): Promise<NaabuResult>;
