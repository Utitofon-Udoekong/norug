import { DetectionRequest, DetectionResponse } from './dtos'
import { parseEther, Interface } from 'ethers'

interface RugPullRisk {
    riskType: string
    severity: 'HIGH' | 'MEDIUM' | 'LOW'
    description: string
    details?: Record<string, unknown>
}

interface FunctionSignature {
    signature: string
    name: string
    severity: 'HIGH' | 'MEDIUM' | 'LOW'
    description: string
    parameterChecks?: (params: any[]) => boolean
}

/**
 * DetectionService for identifying potential rugpull vulnerabilities in smart contracts
 * 
 * Analyzes transaction traces and contract interactions to detect:
 * 1. Hidden admin functions that can drain funds
 * 2. Suspicious withdrawal limitations
 * 3. Ownership concentration risks
 * 4. Malicious contract upgrades
 * 5. Blacklisting capabilities
 */
export class DetectionService {
    // Common signatures that might indicate rugpull capabilities
    private static SUSPICIOUS_SIGNATURES: Record<string, FunctionSignature> = {
        // Ownership and Access Control
        OWNERSHIP_TRANSFER: {
            signature: '0xf2fde38b', // transferOwnership(address)
            name: 'transferOwnership',
            severity: 'HIGH',
            description: 'Ownership transfer detected - potential rugpull preparation',
        },
        RENOUNCE_OWNERSHIP: {
            signature: '0x715018a6', // renounceOwnership()
            name: 'renounceOwnership',
            severity: 'MEDIUM',
            description: 'Ownership renouncement - could be legitimate but verify',
        },

        // Blacklisting and Restrictions
        BLACKLIST: {
            signature: '0xf9f92be4', // addToBlacklist(address)
            name: 'addToBlacklist',
            severity: 'HIGH',
            description: 'Address blacklisting capability - can prevent withdrawals',
        },
        WHITELIST: {
            signature: '0xe43252d7', // addToWhitelist(address)
            name: 'addToWhitelist',
            severity: 'MEDIUM',
            description: 'Whitelist modification - could restrict trading',
        },

        // Contract State Control
        PAUSE: {
            signature: '0x8456cb59', // pause()
            name: 'pause',
            severity: 'MEDIUM',
            description: 'Contract can be paused - might prevent withdrawals',
        },
        SELFDESTRUCT: {
            signature: '0x9cb8a26a', // selfdestruct()
            name: 'selfdestruct',
            severity: 'HIGH',
            description: 'Contract can self-destruct - all funds could be lost',
        },
        UPGRADE: {
            signature: '0x3659cfe6', // upgradeTo(address)
            name: 'upgradeTo',
            severity: 'MEDIUM',
            description: 'Contract is upgradeable - functionality can be changed',
        },

        // Token Operations
        MINT: {
            signature: '0x40c10f19', // mint(address,uint256)
            name: 'mint',
            severity: 'HIGH',
            description: 'Minting capability - could dilute token value',
            parameterChecks: (params) => {
                // Check if minting a large amount
                const amount = BigInt(params[1].toString())
                return amount > parseEther('1000000') // Alert if minting more than 1M tokens
            }
        },
        BURN: {
            signature: '0x42966c68', // burn(uint256)
            name: 'burn',
            severity: 'MEDIUM',
            description: 'Burning capability - verify if authorized',
        },
        SET_FEE: {
            signature: '0x69fe0e2d', // setFee(uint256)
            name: 'setFee',
            severity: 'HIGH',
            description: 'Fee modification capability - could be used for value extraction',
            parameterChecks: (params) => {
                // Alert if fee is set higher than 10%
                const fee = BigInt(params[0].toString())
                return fee > 1000n // Assuming fee is in basis points (1/100 of 1%)
            }
        },

        // Liquidity Control
        REMOVE_LIQUIDITY: {
            signature: '0xbaa2abde', // removeLiquidity(address,uint256)
            name: 'removeLiquidity',
            severity: 'HIGH',
            description: 'Liquidity removal detected - potential rugpull in progress',
        },
        LOCK_TOKENS: {
            signature: '0x5c975abb', // lock(uint256)
            name: 'lock',
            severity: 'MEDIUM',
            description: 'Token locking detected - verify lock duration',
        }
    }

    // Thresholds
    private static OWNERSHIP_CONCENTRATION_THRESHOLD = 50 // 50%
    private static LARGE_BALANCE_DECREASE_THRESHOLD = 80n // 80%
    private static SUSPICIOUS_MINT_THRESHOLD = parseEther('1000000') // 1M tokens
    private static MAX_ACCEPTABLE_FEE = 1000n // 10% in basis points

    /**
     * Analyzes a transaction for potential rugpull risks
     */
    public static detect(request: DetectionRequest): DetectionResponse {
        const risks: RugPullRisk[] = []

        try {
            // Check for suspicious function calls and patterns
            this.analyzeFunctionCalls(request, risks)
            
            // Check for ownership concentration
            this.analyzeOwnershipConcentration(request, risks)
            
            // Check for suspicious state changes
            this.analyzeStateChanges(request, risks)
            
            // Analyze multi-call patterns
            this.analyzeCallPatterns(request, risks)

            // Determine if detection should be triggered based on risks
            const detected = risks.some(risk => risk.severity === 'HIGH')

            return new DetectionResponse({
                request,
                detectionInfo: {
                    detected,
                    message: this.formatRiskMessage(risks),
                },
            })
        } catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred'
            return new DetectionResponse({
                request,
                detectionInfo: {
                    detected: false,
                    error: true,
                    message: `Error analyzing transaction: ${errorMessage}`,
                },
            })
        }
    }

    /**
     * Analyzes function calls in the transaction trace for suspicious patterns
     */
    private static analyzeFunctionCalls(request: DetectionRequest, risks: RugPullRisk[]): void {
        const { trace } = request

        trace.calls?.forEach(call => {
            const functionSig = call.input.slice(0, 10).toLowerCase()
            
            // Check each suspicious signature
            Object.values(this.SUSPICIOUS_SIGNATURES).forEach(suspiciousFunc => {
                if (functionSig === suspiciousFunc.signature) {
                    const risk: RugPullRisk = {
                        riskType: suspiciousFunc.name.toUpperCase(),
                        severity: suspiciousFunc.severity,
                        description: suspiciousFunc.description,
                    }

                    // If there are parameter checks, decode and verify parameters
                    if (suspiciousFunc.parameterChecks && call.input.length > 10) {
                        try {
                            const iface = new Interface([`function ${suspiciousFunc.name}(address,uint256)`])
                            const decoded = iface.decodeFunctionData(suspiciousFunc.name, call.input)
                            
                            if (suspiciousFunc.parameterChecks(decoded)) {
                                risk.details = { parameters: decoded }
                                risks.push(risk)
                            }
                        } catch {
                            // If parameter decoding fails, still add the risk but without details
                            risks.push(risk)
                        }
                    } else {
                        risks.push(risk)
                    }
                }
            })
        })
    }

    /**
     * Analyzes patterns across multiple calls in the transaction
     */
    private static analyzeCallPatterns(request: DetectionRequest, risks: RugPullRisk[]): void {
        const { trace } = request
        const calls = trace.calls || []
        
        // Pattern: Ownership transfer followed by sensitive operations
        const hasOwnershipTransfer = calls.some(call => 
            call.input.startsWith(this.SUSPICIOUS_SIGNATURES.OWNERSHIP_TRANSFER.signature)
        )
        
        if (hasOwnershipTransfer) {
            // Check for sensitive operations after ownership transfer
            const hasSensitiveOps = calls.some(call => {
                const sig = call.input.slice(0, 10).toLowerCase()
                return (
                    sig === this.SUSPICIOUS_SIGNATURES.MINT.signature ||
                    sig === this.SUSPICIOUS_SIGNATURES.REMOVE_LIQUIDITY.signature ||
                    sig === this.SUSPICIOUS_SIGNATURES.SET_FEE.signature
                )
            })

            if (hasSensitiveOps) {
                risks.push({
                    riskType: 'SUSPICIOUS_PATTERN',
                    severity: 'HIGH',
                    description: 'Ownership transfer followed by sensitive operations - high rugpull risk',
                })
            }
        }

        // Pattern: Multiple high-risk operations in single transaction
        const highRiskOps = calls.filter(call => {
            const sig = call.input.slice(0, 10).toLowerCase()
            return Object.values(this.SUSPICIOUS_SIGNATURES)
                .filter(f => f.severity === 'HIGH')
                .some(f => f.signature === sig)
        })

        if (highRiskOps.length > 1) {
            risks.push({
                riskType: 'MULTIPLE_HIGH_RISK_OPS',
                severity: 'HIGH',
                description: `Multiple high-risk operations (${highRiskOps.length}) in single transaction`,
                details: {
                    operationCount: highRiskOps.length,
                    operations: highRiskOps.map(call => call.input.slice(0, 10))
                }
            })
        }
    }

    /**
     * Analyzes token ownership concentration
     */
    private static analyzeOwnershipConcentration(request: DetectionRequest, risks: RugPullRisk[]): void {
        const { pre } = request.trace
        
        // Calculate total supply and largest holder balance
        let totalSupply = parseEther('0')
        let largestBalance = parseEther('0')

        Object.values(pre).forEach(account => {
            if (account.balance) {
                const balance = parseEther(account.balance)
                totalSupply = totalSupply + balance
                if (balance > largestBalance) {
                    largestBalance = balance
                }
            }
        })

        // Check if any address holds more than the threshold
        if (totalSupply > 0n) {
            const concentration = Number((largestBalance * 100n) / totalSupply)
            if (concentration > this.OWNERSHIP_CONCENTRATION_THRESHOLD) {
                risks.push({
                    riskType: 'OWNERSHIP_CONCENTRATION',
                    severity: 'HIGH',
                    description: `Single address holds ${concentration}% of tokens - high rugpull risk`,
                })
            }
        }
    }

    /**
     * Analyzes suspicious state changes that might indicate rugpull preparation
     */
    private static analyzeStateChanges(request: DetectionRequest, risks: RugPullRisk[]): void {
        const { pre, post } = request.trace

        // Check for suspicious balance changes
        Object.keys(pre).forEach(address => {
            const preBalance = parseEther(pre[address]?.balance || '0')
            const postBalance = parseEther(post[address]?.balance || '0')

            // If balance decreased significantly
            if (preBalance > postBalance) {
                const decrease = preBalance - postBalance
                if (decrease > this.LARGE_BALANCE_DECREASE_THRESHOLD) { // 80% decrease
                    risks.push({
                        riskType: 'LARGE_BALANCE_DECREASE',
                        severity: 'HIGH',
                        description: 'Large balance decrease detected - possible rugpull in progress',
                    })
                }
            }
        })
    }

    /**
     * Formats risk messages for human readability
     */
    private static formatRiskMessage(risks: RugPullRisk[]): string {
        if (risks.length === 0) {
            return 'No rugpull risks detected'
        }

        return `Detected ${risks.length} potential rugpull risks:\n` +
            risks.map(risk => `- ${risk.severity} risk: ${risk.description}`).join('\n')
    }
}
