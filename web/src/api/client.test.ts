import { beforeEach, describe, expect, it, vi } from 'vitest'
import { ApiClient } from './client'

describe('ApiClient', () => {
    beforeEach(() => {
        vi.restoreAllMocks()
        vi.stubGlobal('fetch', vi.fn())
    })

    it('adds the Cloudflare Access AJAX header for same-origin auth requests', async () => {
        vi.mocked(fetch).mockResolvedValueOnce(new Response(JSON.stringify({
            token: 'jwt',
            user: { id: 1 }
        }), {
            status: 200,
            headers: { 'content-type': 'application/json' }
        }))

        const client = new ApiClient('')
        await client.authenticate({ accessToken: 'secret' })

        const [, init] = vi.mocked(fetch).mock.calls[0] ?? []
        const headers = new Headers(init?.headers)
        expect(headers.get('content-type')).toBe('application/json')
        expect(headers.get('X-Requested-With')).toBe('XMLHttpRequest')
    })

    it('does not add the Cloudflare Access AJAX header for cross-origin requests', async () => {
        vi.mocked(fetch).mockResolvedValueOnce(new Response(JSON.stringify({
            token: 'jwt',
            user: { id: 1 }
        }), {
            status: 200,
            headers: { 'content-type': 'application/json' }
        }))

        const client = new ApiClient('', { baseUrl: 'https://hub.example.com' })
        await client.authenticate({ accessToken: 'secret' })

        const [, init] = vi.mocked(fetch).mock.calls[0] ?? []
        const headers = new Headers(init?.headers)
        expect(headers.has('X-Requested-With')).toBe(false)
    })

    it('redirects to a top-level reload when same-origin auth receives a non-JSON 401', async () => {
        const onAccessSessionExpired = vi.fn()
        vi.mocked(fetch).mockResolvedValueOnce(new Response('Unauthorized', {
            status: 401,
            headers: { 'content-type': 'text/plain' }
        }))

        const client = new ApiClient('', { onAccessSessionExpired })

        await expect(client.authenticate({ accessToken: 'secret' })).rejects.toThrow(
            'Cloudflare Access session expired. Redirecting to sign in again.'
        )
        expect(onAccessSessionExpired).toHaveBeenCalledTimes(1)
    })

    it('preserves HAPI JSON auth failures without forcing a redirect', async () => {
        const onAccessSessionExpired = vi.fn()
        vi.mocked(fetch).mockResolvedValueOnce(new Response(JSON.stringify({
            error: 'Invalid access token'
        }), {
            status: 401,
            headers: { 'content-type': 'application/json' }
        }))

        const client = new ApiClient('', { onAccessSessionExpired })

        await expect(client.authenticate({ accessToken: 'wrong' })).rejects.toMatchObject({
            status: 401,
            code: 'Invalid access token'
        })
        expect(onAccessSessionExpired).not.toHaveBeenCalled()
    })

    it('redirects general same-origin API requests before retrying auth refresh', async () => {
        const onAccessSessionExpired = vi.fn()
        const onUnauthorized = vi.fn()
        vi.mocked(fetch).mockResolvedValueOnce(new Response('Unauthorized', {
            status: 401,
            headers: { 'content-type': 'text/plain' }
        }))

        const client = new ApiClient('jwt', { onUnauthorized, onAccessSessionExpired })

        await expect(client.getSessions()).rejects.toThrow(
            'Cloudflare Access session expired. Redirecting to sign in again.'
        )
        expect(onAccessSessionExpired).toHaveBeenCalledTimes(1)
        expect(onUnauthorized).not.toHaveBeenCalled()
    })
})
