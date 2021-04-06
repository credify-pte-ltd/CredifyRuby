# Credify

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'credify'
```

And then execute:

    $ bundle install

Or install it yourself as:

    $ gem install credify

## Usage

### Signing

Signing is using EdDSA (curve: Ed25519). The key size is 32 bytes. This SDK uses 32 byte length seed data for importing an existing key.

```ruby
require 'credify'

def new_key_is_generated
  signing = Signing.new
  signing.generate_key_pair
  signature = signing.sign "message"
  valid = signing.verify "message", signature
  puts valid
end

def existing_key_is_used
  signing = Signing.new
  signing.import_seed "-o7hvhS1dJpYanm7fysJdi7j8t1tpKTuUPjou1FS7jg"
  signature = signing.sign "message"
  valid = signing.verify "message", signature
  puts valid
end

def generate_approval_token
  signing = Signing.new
  signing.generate_key_pair
  token = signing.generate_approval_token 'client_id', 'entity_id', ['openid', 'email', 'phone'], 'offer-code'
  puts token
end

def generate_request_token
  signing = Signing.new
  signing.generate_key_pair
  token = signing.generate_request_token 'client_id', 'encryption_public_key', ['openid', 'email', 'phone'], 'offer-code'
  puts token
end

def generate_claim_token
  signing = Signing.new
  signing.generate_key_pair
  result = signing.generate_claim_token 'provider_id', 'entity_id', 'credify-score', { score: 100 }
  puts result
end
```

### Encryption

Encryption is using RSA 4096 bit with OAEP padding. This SDK allows developers to use PKCS8 to deal with keys.

```ruby
require 'credify'

def new_key_is_generated
  encryption = Encryption.new
  encryption.generate_key_pair
  cipher_text = encryption.encrypt "secret message"
  plain_text = encryption.decrypt cipher_text
  pem = encryption.export_private_key
  puts pem
end

def existing_key_is_used
  encryption = Encryption.new
  encryption.import_private_key "-----BEGIN PRIVATE KEY-----\nMI....."
  cipher_text = encryption.encrypt "secret message"
  plain_text = encryption.decrypt cipher_text 
end
```

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).


## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

## Code of Conduct

Everyone interacting in the Credify project's codebases, issue trackers, chat rooms and mailing lists is expected to follow the [code of conduct](https://github.com/[USERNAME]/credify/blob/master/CODE_OF_CONDUCT.md).
