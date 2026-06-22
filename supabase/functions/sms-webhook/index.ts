import { serve } from "https://deno.land/std@0.168.0/http/server.ts"
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'
import * as nostr from 'https://esm.sh/nostr-tools@1.17.0'

const SMS_WEBHOOK_SECRET = Deno.env.get('SMS_WEBHOOK_SECRET')
const SUPABASE_URL = Deno.env.get('SUPABASE_URL')
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')

const PRIMARY_RELAY_POOL = [
  'wss://relay.damus.io',
  'wss://nos.lol',
  'wss://relay.nostr.band',
  'wss://nostr.wine',
  'wss://relay.snort.social'
]

const supabase = createClient(SUPABASE_URL!, SUPABASE_SERVICE_ROLE_KEY!)

serve(async (req) => {
  const url = new URL(req.url)
  const token = url.searchParams.get('token')

  // 1. STRICT MODE: Security Token Check
  if (!token || token !== SMS_WEBHOOK_SECRET) {
    return new Response('Forbidden', { status: 403 })
  }

  try {
    const contentType = req.headers.get('content-type')
    let bodyText = '', from = ''

    // 2. PROVIDER AGNOSTIC PARSER (Twilio & Africa's Talking)
    if (contentType?.includes('application/x-www-form-urlencoded')) {
      const formData = await req.formData()
      bodyText = (formData.get('Body') || formData.get('text') || '').toString().trim()
      from = (formData.get('From') || formData.get('from') || '').toString().trim()
    }

    if (!bodyText.startsWith('ST1')) {
      return new Response('<?xml version="1.0" encoding="UTF-8"?><Response></Response>', { headers: { 'Content-Type': 'text/xml' } })
    }

    // 3. FRAGMENT REASSEMBLY (Barrier S2)
    let fullPayload = ''
    const senderHash = await hashString(from)

    if (bodyText.startsWith('ST1/')) {
      // Format: ST1/[part]/[total]:[payload]
      const [meta, payload] = bodyText.split(':')
      const [, part, total] = meta.split('/')
      
      const { data: inserted } = await supabase.from('sms_fragments').insert({
        sender_hash: senderHash,
        total_parts: parseInt(total),
        part_number: parseInt(part),
        payload: payload
      }).select()

      // Check if complete
      const { data: fragments } = await supabase
        .from('sms_fragments')
        .select('*')
        .eq('sender_hash', senderHash)
        .eq('total_parts', parseInt(total))
        .eq('assembled', false)
        .order('part_number', { ascending: true })

      if (fragments && fragments.length === parseInt(total)) {
        fullPayload = fragments.map(f => f.payload).join('')
        // Mark as assembled
        await supabase.from('sms_fragments').update({ assembled: true }).eq('sender_hash', senderHash)
      } else {
        // Wait for more fragments
        return new Response('<?xml version="1.0" encoding="UTF-8"?><Response></Response>', { headers: { 'Content-Type': 'text/xml' } })
      }
    } else {
      // Single part: ST1:[payload]
      fullPayload = bodyText.slice(4)
    }

    // 4. DECODE & STRATEGY
    const eventData = JSON.parse(atob(fullPayload))
    // We assume the client has provided enough to reconstruct the minimal event for validation
    // ST1 stripped keys: i (id), p (pubkey), s (sig), c (content), a (created_at)
    const nostrEvent = {
        id: eventData.i,
        pubkey: eventData.p,
        created_at: eventData.a,
        kind: 10001,
        tags: [['t', 'sos'], ['p', eventData.p]],
        content: eventData.c,
        sig: eventData.s
    }

    // 5. SIGNATURE VALIDATION (Section 1.4)
    const isValid = nostr.validateEvent(nostrEvent) && nostr.verifySignature(nostrEvent)
    if (!isValid) {
      console.error('[BRIDGE] Invalid Signature Rejected')
      return new Response('Invalid Signature', { status: 200 }) // Return 200 to stop retries
    }

    // 6. PARALLEL RELAY BROADCAST
    const relayPool = PRIMARY_RELAY_POOL 
    const results = {}
    
    await Promise.all(relayPool.map(async (relayUrl) => {
      try {
        results[relayUrl] = await broadcastEvent(relayUrl, nostrEvent)
      } catch (e) {
        results[relayUrl] = false
      }
    }))

    const successCount = Object.values(results).filter(v => v === true).length
    const finalStatus = successCount >= 2 ? 'CONFIRMED' : (successCount > 0 ? 'PARTIAL' : 'FAILED')

    // 7. AUDIT LOGGING
    await supabase.from('sms_broadcast_logs').insert({
      event_id_prefix: nostrEvent.id.slice(0, 8),
      sender_hash: senderHash,
      relay_results: results,
      status: finalStatus
    })

    // 8. TWIML RESPONSE
    const replyText = successCount >= 2 ? `ST-OK:${nostrEvent.id.slice(0, 8)}` : `ST-FAIL`
    return new Response(`<?xml version="1.0" encoding="UTF-8"?><Response><Message>${replyText}</Message></Response>`, {
        headers: { 'Content-Type': 'text/xml' }
    })

  } catch (err) {
    console.error('[CRITICAL ERROR]', err)
    return new Response('Internal Error', { status: 200 })
  }
})

async function hashString(str: string) {
  const msgUint8 = new TextEncoder().encode(str)
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8)
  const hashArray = Array.from(new Uint8Array(hashBuffer))
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('')
}

async function broadcastEvent(url: string, event: any): Promise<boolean> {
  return new Promise((resolve) => {
    const ws = new WebSocket(url)
    const timer = setTimeout(() => { ws.close(); resolve(false) }, 8000)
    ws.onopen = () => ws.send(JSON.stringify(['EVENT', event]))
    ws.onmessage = (msg) => {
        try {
            const [type, id, ok] = JSON.parse(msg.data)
            if (type === 'OK' && id === event.id && ok) {
                clearTimeout(timer)
                ws.close()
                resolve(true)
            }
        } catch(e) {}
    }
    ws.onerror = () => { ws.close(); resolve(false) }
  })
}
