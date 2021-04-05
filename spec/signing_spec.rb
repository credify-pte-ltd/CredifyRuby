require 'rspec'
require 'credify/signing'
require 'base64'

RSpec.describe Signing do

  let(:signature) { 'olq3UTFEdJAgYpN1JifKRhhci9LGjwmZ83NtlHGpT19T5uJdEaPc7CTfW_hL3V-Gyoblt6LXfbqw0yfXOAoTBQ' }
  let(:message) { 'This is a test message!' }
  let(:seed) { 'UseZb/HIOiqrYSLqVmMdbiILuLTdiGRA3hZ3QwiEiBU=' }

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

    it 'exports 32 byte seed' do
      @s.generate_key_pair
      seed = @s.export_seed
      expect(Base64.decode64(seed).length).to eq 32
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
end