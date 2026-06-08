export interface HttpxResult {
    responses: Array<{
        url: string;
        statusCode?: number;
        contentLength?: number;
        title?: string;
        webserver?: string;
    }>;
    count: number;
    error?: string;
}
export declare function executeHttpx(urls: string[], followRedirects?: boolean, screenshot?: boolean): Promise<HttpxResult>;
