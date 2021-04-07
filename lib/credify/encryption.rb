require 'openssl'
require 'openssl/oaep'
require "base64"
require 'openssl_pkcs8_pure'
require 'credify'

class Encryption
  attr_reader :private_key, :public_key

  #
  # generate_key_pair
  # @return [Boolean]
  def generate_key_pair
    key = OpenSSL::PKey::RSA.generate(4096, 17)
    @private_key = key
    @public_key = key.public_key
    @private_key.nil?
  end

  #
  # import_private_key
  # @param [String] pem
  # @return [Boolean]
  def import_private_key(pem)
    key = OpenSSL::PKey::RSA.new pem
    @private_key = key
    @public_key = key.public_key
    @private_key.nil?
  end

  #
  # import_public_key
  # @param [String] pem
  # @return [Boolean]
  def import_public_key(pem)
    key = OpenSSL::PKey::RSA.new pem
    # @private_key = key
    @public_key = key.public_key
    @public_key.nil?
  end

  #
  # import_private_key_base64_url
  # @param [String] payload - Base64 URL encoded string
  # @return [Boolean]
  def import_private_key_base64_url(payload)
    bytes = Credify::Helpers.short_urlsafe_decode64(payload)
    base64 = Base64.encode64(bytes)
    formatted = base64.scan(/.{1,64}/).join("\n")
    pem = add_box('PRIVATE KEY', formatted)
    import_private_key(pem)
  end

  #
  # import_public_key_base64_url
  # @param [String] payload - Base64 URL encoded string
  # @return [Boolean]
  def import_public_key_base64_url(payload)
    bytes = Credify::Helpers.short_urlsafe_decode64(payload)
    base64 = Base64.encode64(bytes)
    formatted = base64.scan(/.{1,64}/).join("\n")
    pem = add_box('PUBLIC KEY', formatted)
    import_public_key(pem)
  end

  #
  # encrypt
  # @param [String] message
  # @return [String] Base64 URL encoded string after encryption
  def encrypt(message)
    if @public_key.nil?
      raise Exception.new 'Please pass public key'
    end
    label = ''
    md = OpenSSL::Digest::SHA256
    cipher_text = @public_key.public_encrypt_oaep(message, label, md)
    Credify::Helpers.short_urlsafe_encode64(cipher_text)
  end

  #
  # decrypt
  # @param [String] cipher - Base64 URL encoded cipher text
  # @return [String] Plain text
  def decrypt(cipher)
    if @private_key.nil?
      raise Exception.new 'Please pass private key'
    end
    label = ''
    md = OpenSSL::Digest::SHA256
    raw_cipher = Credify::Helpers.short_urlsafe_decode64(cipher)
    raw_text = @private_key.private_decrypt_oaep(raw_cipher, label, md)
    raw_text
  end

  #
  # export_private_key
  # @param [Boolean] in_base64_url
  # @return [Signing | String] - PCKS8 PEM or Base64 URL encoded string
  def export_private_key(in_base64_url = false)
    if @private_key.nil?
      raise Exception.new 'Please pass private key'
    end
    pem = @private_key.to_pem_pkcs8.gsub(/#{$/}$/, "")

    if in_base64_url
      formatted = remove_box('PRIVATE KEY', pem)
      Credify::Helpers.short_urlsafe_encode64(Base64.decode64(formatted))
    else
      pem
    end
  end

  #
  # export_public_key
  # @param [Boolean] in_base64_url
  # @return [Signing | String] - PCKS8 PEM or Base64 URL encoded string
  def export_public_key(in_base64_url = false)
    if @public_key.nil?
      raise Exception.new 'Please pass public key'
    end

    pem = @public_key.to_pem_pkcs8.gsub(/#{$/}$/, "")

    if in_base64_url
      formatted = remove_box('PUBLIC KEY', pem)
      Credify::Helpers.short_urlsafe_encode64(Base64.decode64(formatted))
    else
      pem
    end
  end


  protected

  #
  # remove_box
  # @param [String] tag - Either 'PUBLIC KEY' or 'PRIVATE KEY'
  # @param [String] pem - String value loaded from a PEM file
  # @return [String] - Base64 encoded string in PEM file
  def remove_box(tag, pem)
    tmp = pem.gsub("-----BEGIN #{tag}-----", '')
    tmp = tmp.gsub("-----END #{tag}-----", '')
    tmp.gsub(/\n/, '')
  end

  #
  # add_box
  # @param [String] tag - Either 'PUBLIC KEY' or 'PRIVATE KEY'
  # @param [String] base64 - Base64 encoded string
  # @return [String] - PEM
  def add_box(tag, base64)
    payload = base64.scan(/.{1,64}/).join("\n")
    "-----BEGIN #{tag}-----\n" << payload << "\n-----END #{tag}-----"
  end

end