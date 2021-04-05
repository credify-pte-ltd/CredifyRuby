require "ed25519"
require "base64"
require 'openssl_pkcs8_pure'

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
  # @param [String] seed - Base64 encoded 32 byte seed data
  # @return [Boolean]
  def import_seed(seed)
    @signing_key = Ed25519::SigningKey.new(Base64.decode64(seed))
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
    short_urlsafe_encode64(signature)
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
    raw_sign = short_urlsafe_decode64(signature)
    @signing_key.verify_key.verify raw_sign, message
  end

  # export_seed
  # @return [String] - Base64 encoded 32 bytes seed data
  def export_seed
    if @signing_key.nil?
      raise Exception.new 'Please pass signing key'
    end
    Base64.encode64(@signing_key.seed)
  end

  protected

  #
  # short_urlsafe_encode64
  # @param [Binary] - str
  # @return [String] - Base64 URL encoded string without padding
  def short_urlsafe_encode64(bytes)
    Base64.urlsafe_encode64(bytes).delete('=')
  end

  #
  # short_urlsafe_decode64
  # @return [Binary]
  def short_urlsafe_decode64(str)
    Base64.urlsafe_decode64(str + '=' * (-1 * str.size & 3))
  end

end