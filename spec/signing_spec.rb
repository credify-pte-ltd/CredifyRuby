require 'rspec'
require 'credify/signing'
require 'base64'

RSpec.describe Signing do

  let(:signature) { 'oJ6yDFkgsQk8wMqLQm2vtBVKxJ69fH2oU5SYIrCaTy5RjHdpIFBT_UV8I8PbJj_Gv7ll2bc2FFGepURUC23SBg' }
  let(:message) { 'This is a test message!' }
  let(:seed) { '-o7hvhS1dJpYanm7fysJdi7j8t1tpKTuUPjou1FS7jg' }

  before do
    @s = Signing.new
  end

  after do
    # Do nothing
  end

  context 'when any key is not passed and new key is generated' do
    it 'succeeds to use a new key pair' do
      @s.generate_key_pair
      sign = @s.sign(message)
      expect(sign).not_to be nil
      valid = @s.verify(sign, message)
      expect(valid).to be_truthy
    end
  end

  context 'when any key is not passed and new key is not generated' do
    it 'should raise an error in sign' do
      expect { @s.sign(message) }.to raise_error 'Please pass signing key'
    end

    it 'should raise an error in verify' do
      expect { @s.verify(signature, message) }.to raise_error 'Please pass signing key'
    end

    it 'should raise an error in export_seed' do
      expect { @s.export_seed }.to raise_error 'Please pass signing key'
    end
  end

  context 'when an existing key is passed' do
    it 'succeeds to generate the same signature' do
      @s.import_seed(seed)
      sign = @s.sign(message)
      expect(sign).to eq signature
    end

    it 'succeeds to validate the signature' do
      @s.import_seed(seed)
      valid = @s.verify(signature, message)
      expect(valid).to be_truthy
    end
  end

  context 'when a user uses JWT' do
    it 'succeeds to generate approval token' do
      @s.import_seed(seed)
      token = @s.generate_approval_token('client_id', 'entity_id', ['openid', 'email', 'phone'])
      expect(token).to start_with('ey')
      parsed_jwt = @s.parse_jwt(token)
      expect(@s.verify_jwt(parsed_jwt)).to be_truthy
    end

    it 'succeeds to generate request token' do
      @s.import_seed(seed)
      token = @s.generate_request_token('client_id', 'encryption_public_key', ['openid', 'email', 'phone'])
      expect(token).to start_with('ey')
      parsed_jwt = @s.parse_jwt(token)
      expect(@s.verify_jwt(parsed_jwt)).to be_truthy
    end

    it 'succeeds to generate claim token' do
      @s.import_seed(seed)
      result = @s.generate_claim_token('provider_id', 'entity_id', 'credify-score', { score: 100 })
      expect(result).to include({ :token => a_string_starting_with('ey'), :commitment => be_a(String) })
      parsed_jwt = @s.parse_jwt(result[:token])
      expect(@s.verify_jwt(parsed_jwt)).to be_truthy
    end

  end
end