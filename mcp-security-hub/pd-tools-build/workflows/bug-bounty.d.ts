export interface RateLimitOptions {
    maxCrawlUrls?: number;
    maxScanUrls?: number;
    maxTopPorts?: number;
    batchSize?: number;
    delayBetweenBatches?: number;
    crawlDepth?: number;
}
export interface BugBountyWorkflowOptions {
    portScan: boolean;
    crawl: boolean;
    vulnerabilityScan: boolean;
    severityFilter?: string[];
    rateLimit?: RateLimitOptions;
}
export interface BugBountyWorkflowResult {
    summary: {
        domain: string;
        totalSubdomains: number;
        totalResolvedHosts: number;
        totalOpenPorts: number;
        totalLiveHosts: number;
        totalEndpoints: number;
        totalVulnerabilities: number;
        criticalFindings: number;
        highFindings: number;
        executionTime: number;
    };
    steps: {
        subdomainDiscovery?: any;
        dnsResolution?: any;
        portScanning?: any;
        httpProbing?: any;
        webCrawling?: any;
        vulnerabilityScanning?: any;
    };
    findings: any[];
}
export declare function runBugBountyWorkflow(domain: string, options: BugBountyWorkflowOptions): Promise<BugBountyWorkflowResult>;
