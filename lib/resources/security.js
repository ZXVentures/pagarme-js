/**
 * @name Security
 * @description This module exposes functions
 *              related to security procedures.
 *
 * @module security
 **/
import NodeRSA from 'node-rsa'
import Promise from 'bluebird'
import qs from 'qs'
import {
  toString,
  replace,
  pipe,
} from 'ramda'

const cleanNumber = pipe(
  toString,
  replace(/[^0-9]/g, '')
)

const queryString = card =>
  qs.stringify({
    card_number: cleanNumber(card.card_number),
    card_holder_name: card.card_holder_name,
    card_expiration_date: cleanNumber(card.card_expiration_date),
    card_cvv: cleanNumber(card.card_cvv),
  })

const generateCardHash = ({ public_key: publicKey, id }, cardString) => {
  const key = new NodeRSA(publicKey, {
    encryptionScheme: 'pkcs1',
  })
  const encrypted = key.encrypt(cardString, 'base64')
  const cardHash = `${id}_${encrypted}`
  return cardHash
}

/**
 * Encrypt a card object into a card_hash
 *
 * @param {Object} opts An options params which
 *                      is usually already bound
 *                      by `connect` functions.
 *
 * @param {Object} card The card object.
 * {@link https://pagarme.readme.io/v1/reference#gerando-card_hash-manualmente|API Reference for this payload}
 *
 * @param {String} card.card_number The card's number.
 *                             Example: '4111111111111111'
 * @param {String} card.card_holder_name The card's holder name.
 *                             Example: 'Pedro Paulo'
 * @param {String} card.card_expiration_date The card's expiration date.
 *                             Example: '1225' or '12/25'
 * @param {String} card.card_cvv The card's cvv.
 *                             Example: '543'
*/
const encrypt = (opts, card) =>
  Promise.props({
    key: card.key,
    cardString: queryString(card),
  })
    .then(({ key, cardString }) => generateCardHash(key, cardString))

const generateCardHashSha256 = ({ publicKey }, cardString) => {
  const key = new NodeRSA(publicKey, 'pkcs8-public', {
    encryptionScheme: {
      hash: 'sha256',
    },
  })

  const encrypted = key.encrypt(cardString, 'base64')

  return encrypted
}

export default {
  encrypt,
  generateCardHashSha256,
}
