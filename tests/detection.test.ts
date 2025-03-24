import { DetectionRequest } from '../src/modules/detection-module/dtos'
import { DetectionService } from '../src/modules/detection-module/service'

describe('Rugpull Detector Tests', () => {
    const baseRequest: Partial<DetectionRequest> = {
        chainId: 1,
        hash: '0x123',
        trace: {
            blockNumber: 1,
            from: '0x123',
            to: '0x456',
            transactionHash: '0x123',
            input: '0x',
            output: '0x',
            gas: '100000',
            gasUsed: '50000',
            value: '0',
            calls: [],
            logs: [],
            pre: {},
            post: {}
        }
    }

    describe('Function Call Detection', () => {
        it('should detect ownership transfer as high risk', () => {
            const request: DetectionRequest = {
                ...baseRequest,
                trace: {
                    ...baseRequest.trace!,
                    calls: [{
                        from: '0x123',
                        to: '0x456',
                        input: '0xf2fde38b0000000000000000000000001234567890123456789012345678901234567890',
                        output: '0x',
                        gasUsed: '50000',
                        value: '0'
                    }]
                }
            } as DetectionRequest

            const result = DetectionService.detect(request)
            expect(result.detected).toBe(true)
            expect(result.message).toContain('OWNERSHIP_TRANSFER')
            expect(result.message).toContain('HIGH risk')
        })

        it('should detect blacklist function as high risk', () => {
            const request: DetectionRequest = {
                ...baseRequest,
                trace: {
                    ...baseRequest.trace!,
                    calls: [{
                        from: '0x123',
                        to: '0x456',
                        input: '0xf9f92be40000000000000000000000001234567890123456789012345678901234567890',
                        output: '0x',
                        gasUsed: '50000',
                        value: '0'
                    }]
                }
            } as DetectionRequest

            const result = DetectionService.detect(request)
            expect(result.detected).toBe(true)
            expect(result.message).toContain('BLACKLIST')
            expect(result.message).toContain('HIGH risk')
        })
    })

    describe('Token Concentration Detection', () => {
        it('should detect high token concentration', () => {
            const request: DetectionRequest = {
                ...baseRequest,
                trace: {
                    ...baseRequest.trace!,
                    pre: {
                        '0x123': { balance: '600000000000000000000', nonce: 1 },
                        '0x456': { balance: '400000000000000000000', nonce: 1 }
                    }
                }
            } as DetectionRequest

            const result = DetectionService.detect(request)
            expect(result.detected).toBe(true)
            expect(result.message).toContain('OWNERSHIP_CONCENTRATION')
            expect(result.message).toContain('HIGH risk')
        })

        it('should not detect normal token distribution', () => {
            const request: DetectionRequest = {
                ...baseRequest,
                trace: {
                    ...baseRequest.trace!,
                    pre: {
                        '0x123': { balance: '300000000000000000000', nonce: 1 },
                        '0x456': { balance: '300000000000000000000', nonce: 1 },
                        '0x789': { balance: '400000000000000000000', nonce: 1 }
                    }
                }
            } as DetectionRequest

            const result = DetectionService.detect(request)
            expect(result.detected).toBe(false)
        })
    })

    describe('Balance Change Detection', () => {
        it('should detect large balance decrease', () => {
            const request: DetectionRequest = {
                ...baseRequest,
                trace: {
                    ...baseRequest.trace!,
                    pre: {
                        '0x123': { balance: '1000000000000000000000', nonce: 1 }
                    },
                    post: {
                        '0x123': { balance: '100000000000000000000', nonce: 1 }
                    }
                }
            } as DetectionRequest

            const result = DetectionService.detect(request)
            expect(result.detected).toBe(true)
            expect(result.message).toContain('LARGE_BALANCE_DECREASE')
            expect(result.message).toContain('HIGH risk')
        })

        it('should not detect normal balance changes', () => {
            const request: DetectionRequest = {
                ...baseRequest,
                trace: {
                    ...baseRequest.trace!,
                    pre: {
                        '0x123': { balance: '1000000000000000000000', nonce: 1 }
                    },
                    post: {
                        '0x123': { balance: '900000000000000000000', nonce: 1 }
                    }
                }
            } as DetectionRequest

            const result = DetectionService.detect(request)
            expect(result.detected).toBe(false)
        })
    })

    describe('Error Handling', () => {
        it('should handle invalid input gracefully', () => {
            const request: DetectionRequest = {
                ...baseRequest,
                trace: {
                    ...baseRequest.trace!,
                    pre: {
                        '0x123': { balance: 'invalid', nonce: 1 }
                    }
                }
            } as DetectionRequest

            const result = DetectionService.detect(request)
            expect(result.error).toBe(true)
            expect(result.detected).toBe(false)
            expect(result.message).toContain('Error analyzing transaction')
        })
    })

    describe('Enhanced Detection Tests', () => {
        it('should detect suspicious mint with large amount', () => {
            const request: DetectionRequest = {
                ...baseRequest,
                trace: {
                    ...baseRequest.trace!,
                    calls: [{
                        from: '0x123',
                        to: '0x456',
                        input: '0x40c10f190000000000000000000000001234567890123456789012345678901234567890000000000000000000000000000000000000000000d3c21bcecceda1000000', // mint 1M tokens
                        output: '0x',
                        gasUsed: '50000',
                        value: '0'
                    }]
                }
            } as DetectionRequest

            const result = DetectionService.detect(request)
            expect(result.detected).toBe(true)
            expect(result.message).toContain('MINT')
            expect(result.message).toContain('HIGH risk')
        })

        it('should detect suspicious pattern of ownership transfer and mint', () => {
            const request: DetectionRequest = {
                ...baseRequest,
                trace: {
                    ...baseRequest.trace!,
                    calls: [
                        {
                            from: '0x123',
                            to: '0x456',
                            input: '0xf2fde38b0000000000000000000000001234567890123456789012345678901234567890', // transferOwnership
                            output: '0x',
                            gasUsed: '50000',
                            value: '0'
                        },
                        {
                            from: '0x123',
                            to: '0x456',
                            input: '0x40c10f190000000000000000000000001234567890123456789012345678901234567890000000000000000000000000000000000000000000d3c21bcecceda1000000', // mint
                            output: '0x',
                            gasUsed: '50000',
                            value: '0'
                        }
                    ]
                }
            } as DetectionRequest

            const result = DetectionService.detect(request)
            expect(result.detected).toBe(true)
            expect(result.message).toContain('SUSPICIOUS_PATTERN')
            expect(result.message).toContain('HIGH risk')
        })

        it('should detect excessive fee setting', () => {
            const request: DetectionRequest = {
                ...baseRequest,
                trace: {
                    ...baseRequest.trace!,
                    calls: [{
                        from: '0x123',
                        to: '0x456',
                        input: '0x69fe0e2d0000000000000000000000000000000000000000000000000000000000000bb8', // setFee to 30% (3000 basis points)
                        output: '0x',
                        gasUsed: '50000',
                        value: '0'
                    }]
                }
            } as DetectionRequest

            const result = DetectionService.detect(request)
            expect(result.detected).toBe(true)
            expect(result.message).toContain('SET_FEE')
            expect(result.message).toContain('HIGH risk')
        })

        it('should detect multiple high-risk operations', () => {
            const request: DetectionRequest = {
                ...baseRequest,
                trace: {
                    ...baseRequest.trace!,
                    calls: [
                        {
                            from: '0x123',
                            to: '0x456',
                            input: '0xf2fde38b0000000000000000000000001234567890123456789012345678901234567890', // transferOwnership
                            output: '0x',
                            gasUsed: '50000',
                            value: '0'
                        },
                        {
                            from: '0x123',
                            to: '0x456',
                            input: '0xbaa2abde0000000000000000000000001234567890123456789012345678901234567890', // removeLiquidity
                            output: '0x',
                            gasUsed: '50000',
                            value: '0'
                        }
                    ]
                }
            } as DetectionRequest

            const result = DetectionService.detect(request)
            expect(result.detected).toBe(true)
            expect(result.message).toContain('MULTIPLE_HIGH_RISK_OPS')
            expect(result.message).toContain('HIGH risk')
        })
    })
}) 