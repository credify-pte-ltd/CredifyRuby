require "ed25519"
require "base64"
require 'json'
require 'openssl_pkcs8_pure'
require 'credify'

class Signing
  attr_reader :signing_key

  #
  # generate_key_pair
  # @return [Boolean]
  def generate_key_pair
    @signing_key = Ed25519::SigningKey.generate
    @signing_key.nil?
  end

  #
  # import_seed
  # @param [String] seed - Base64 URL encoded seed data
  # @return [Boolean]
  def import_seed(seed)
    binary = Credify::Helpers.short_urlsafe_decode64(seed)
    @signing_key = Ed25519::SigningKey.new(binary)
    @signing_key.nil?
  end

  #
  # sign
  # @param [String] message - String value you want to sign
  # @return [String] - Base64 URL encoded signature
  def sign(message)
    if @signing_key.nil?
      raise Exception.new 'Please pass signing key'
    end
    signature = @signing_key.sign(message)
    Credify::Helpers.short_urlsafe_encode64(signature)
  end

  #
  # verify
  # @param [String] signature - Base64 URL encoded signature
  # @param [String] message - Plain text to be signed
  # @return [Boolean]
  def verify(signature, message)
    if @signing_key.nil?
      raise Exception.new 'Please pass signing key'
    end
    raw_sign = Credify::Helpers.short_urlsafe_decode64(signature)
    @signing_key.verify_key.verify raw_sign, message
  end

  #
  # export_seed
  # @return [String] - Base64 URL encoded seed data
  def export_seed
    if @signing_key.nil?
      raise Exception.new 'Please pass signing key'
    end
    Credify::Helpers.short_urlsafe_encode64(@signing_key.seed)
  end

  #
  # generate_jwt
  # @param [Hash] payload
  # @return [String]
  def generate_jwt(payload)
    if payload.empty?
      raise Exception.new 'Invalid payload'
    end
    header = {
      alg: 'EdDSA',
      typ: 'JWT'
    }
    message = compose_message(header, payload)
    signature = sign(message)
    message << '.' << signature
  end

  #
  # parse_jwt
  # @param [String] jwt
  # @return [Hash] - { header: '', payload: {}, signature: '' }
  def parse_jwt(jwt)
    components = jwt.split('.')
    unless components.length == 3
      raise Exception 'JST is invalid'
    end

    header = JSON.parse(Credify::Helpers.short_urlsafe_decode64(components[0]))
    payload = JSON.parse(Credify::Helpers.short_urlsafe_decode64(components[1]))
    { header: header, payload: payload, signature: components[2] }
  end

  #
  # verify_jwt
  # @param [Hash] jwt - { header: '', payload: {}, signature: '' }
  # @return [Boolean]
  def verify_jwt(jwt)
    message = compose_message(jwt[:header], jwt[:payload])
    verify(jwt[:signature], message)
  end

  #
  # generate_approval_token
  # @param [String] client_id
  # @param [String] entity_id
  # @param [String[]] approved_scopes
  # @param [String | nil] offer_code
  # @return [String]
  def generate_approval_token(client_id, entity_id, approved_scopes, offer_code = nil)
    # minus 60 just in case this timestamp could collide one in the server side.
    now = Time.now.to_i - 60
    payload = {
      client_id: client_id,
      iat: now,
      iss: entity_id,
      scopes: approved_scopes.join(' ')
    }
    unless offer_code.nil?
      payload[:offer_code] = offer_code
    end
    generate_jwt(payload)
  end

  #
  # generate_claim_token
  # @param [String] provider_id
  # @param [String] entity_id
  # @param [String] scope_name
  # @param [Hash] claim
  # @return [Hash]
  def generate_claim_token(provider_id, entity_id, scope_name, claim)
    # minus 60 just in case this timestamp could collide one in the server side.
    now = Time.now.to_i - 60
    commitment = Credify::Helpers.generate_commitment
    data = claim[:"#{scope_name}:commitment"] = commitment
    scope_hash = Credify::Helpers.sha256(data)
    puts scope_hash
    payload = {
      iat: now,
      iss: provider_id,
      user_id: entity_id,
      scope_name: scope_name,
      scope_hash: scope_hash
    }
    token = generate_jwt(payload)
    { token: token, commitment: commitment }
  end

  #
  # generate_request_token
  # @param [String] client_id
  # @param [String] encryption_public_key - Encryption public key in Base64 URL
  # @param [String[]] scopes
  # @param [String | nil] offer_code
  # @return [String]
  def generate_request_token(client_id, encryption_public_key, scopes, offer_code = nil)
    unless scopes.include?('openid')
      raise Exception 'scopes need to contain openid'
    end
    # minus 60 just in case this timestamp could collide one in the server side.
    now = Time.now.to_i - 60
    payload = {
      iat: now,
      iss: client_id,
      encryption_public_key: encryption_public_key,
      scopes: scopes.join(' ')
    }
    unless offer_code.nil?
      payload[:offer_code] = offer_code
    end
    generate_jwt(payload)
  end

  protected


  # compose_message
  # @param [Hash] header
  # @param [Hash] payload
  # @return [String]
  def compose_message(header, payload)
    encoded_header = header.to_json
    h = Credify::Helpers.short_urlsafe_encode64(encoded_header)

    encoded_payload = payload.to_json
    p = Credify::Helpers.short_urlsafe_encode64(encoded_payload)

    h << '.' << p
  end

end