require "credify/version"
require 'base64'
require 'securerandom'

module Credify
  class Error < StandardError; end

  class Helpers
    def self.sha256(message)
      base64 = Digest::SHA256.base64digest(message)
      Helpers.short_urlsafe_encode64(Base64.decode64(base64))
    end

    #
    # short_urlsafe_encode64
    # @param [Binary] - str
    # @return [String] - Base64 URL encoded string without padding
    def self.short_urlsafe_encode64(bytes)
      Base64.urlsafe_encode64(bytes).delete('=')
    end

    #
    # short_urlsafe_decode64
    # @return [Binary]
    def self.short_urlsafe_decode64(str)
      Base64.urlsafe_decode64(str + '=' * (-1 * str.size & 3))
    end

    def self.generate_commitment(bytes = 32)
      random_bytes = SecureRandom.random_bytes(bytes)
      short_urlsafe_encode64(random_bytes)
    end

  end

end
