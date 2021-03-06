require 'rspec'
require 'credify/encryption'

RSpec.describe Encryption do

  let(:cipher) { 'YDLM-8gTpqBgQzvYRqasgv-_u5Jthawk0cTJJSlRJIACJCYsB6u7LJpAiE5vHxa8B1yQ4Vg5w271X2seMwXEJn4xpbM44lUqAUpItdmGcsktVaEB2lpf7_GqMv6XEhOjc1JoanGm3tp6vySmcWv8g-XWZVmusiJKfvnppJKSoaxpT2C3aZ1dzLlMZdVssen6Cz1D3agspzi_hG8v-t7tbeV-g7jKPmXAKJswwahAkJgXs7pJzQ-GGSXksbKGr11Z0XkM-mivaX0w1B6GQcQIYYUi_0IoPEUzTc1Mpv6LErtJryXnlCUKAo5u1a8WpLjEPlrhCBJiXXX63a7dGmE37pjhs5Bw74MJK6Y8chFHpAUemJnZbfs8gY2RGh-Nkt6jeNSpJ2IrDSAPfvhFHbSxrEhNuSVy0KCdi_xqGGD40bmI8QIgTfmusFHMW3iCKm1yAD-55R745vNvAto69FIA--Ek6Gle8Z3eKSPKBgfZE3NbKpATExMU1LU1mhCffOdG6hKUvTrsEBN_ob3UOn6g9JcaiPH9ezAe1bB48U3-TsyJ-ypNKWOxV46B2VsKnQgL-ire8T4ZCck-32usUWAlhFPUkXxTYYNSej2CXZY8ukSpdED5vy-D_g-xiWn9MI51oL2XUONc8KvOd1KlUf87OYwdS0EDFlOWu1DlsUTaYnk' }
  let(:message) { 'This is a test message!' }
  let(:private_key_pem) { '-----BEGIN PRIVATE KEY-----
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
osQZlO5eDVv0XR3aNy5pOR/ouC0o8a8=
-----END PRIVATE KEY-----' }
  let(:public_key_pem) { '-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA6xGr1bqTn/hu1PN6IdEy
iytFPvQXWOHIDwnuuoMi6HWPTRe/q/TYGR5bEjml10whCTqPP62/iRVt+K5pkSAq
epoXgf3R8LltVU4ESu11tYW/A4QPBqJTMHS3zx62iLiaE67XYMcxF0jTh9HnJhOC
nRw7z9f4+/VRd0TrjYeptsdjHl+YqS9bym/ZTZtfGfnMFvIjfdNKFD4dtQ3G8kuA
VH0rHXDq4M86GZ+3WpgEAHZSLqav1geOwJDlxoDoKwLI1ca1wJDjbe24vOzmvxyJ
75Xh0Fhus9rK8L0/t3Ptwg1C6JKLuNmbprp6+qvs4/8heLURlDmoLZDGdkkeA1W0
Ys99wTU/D+eB7eWAMUPHKvesoF8AF58+pzUg7EtPUtgNiy/24888zVSRk8Skp8Qt
Tf4xv5KlJu4s696tbEEKjU+QucpQ5/+QfoGUvOFdoj/j92tsKnfzz3kC8d15mNex
k3x8nws8HZtLvpUhLLvLCekoKYsQQkrgsT6LgvdJEqyNXeMncSUQj4VH46L3Cqaq
eMJSyx0zUd1hzJQ0l+adgxCYYXrt9qYYkauJzabO1htiBUJZNxuuu0K1tAAe5dBV
q2G45EPi7us27mGTUH/vu1nNb4wztoBDb40Ehjjfbuidz+Hk7zE8oexHiAaXFFXI
Bo7iHDNn/q58akCJ6edjGUECAwEAAQ==
-----END PUBLIC KEY-----' }
  let(:private_key_base64_url) { 'MIIJQwIBADANBgkqhkiG9w0BAQEFAASCCS0wggkpAgEAAoICAQDrEavVupOf-G7U83oh0TKLK0U-9BdY4cgPCe66gyLodY9NF7-r9NgZHlsSOaXXTCEJOo8_rb-JFW34rmmRICp6mheB_dHwuW1VTgRK7XW1hb8DhA8GolMwdLfPHraIuJoTrtdgxzEXSNOH0ecmE4KdHDvP1_j79VF3ROuNh6m2x2MeX5ipL1vKb9lNm18Z-cwW8iN900oUPh21DcbyS4BUfSsdcOrgzzoZn7damAQAdlIupq_WB47AkOXGgOgrAsjVxrXAkONt7bi87Oa_HInvleHQWG6z2srwvT-3c-3CDULokou42Zumunr6q-zj_yF4tRGUOagtkMZ2SR4DVbRiz33BNT8P54Ht5YAxQ8cq96ygXwAXnz6nNSDsS09S2A2LL_bjzzzNVJGTxKSnxC1N_jG_kqUm7izr3q1sQQqNT5C5ylDn_5B-gZS84V2iP-P3a2wqd_PPeQLx3XmY17GTfHyfCzwdm0u-lSEsu8sJ6SgpixBCSuCxPouC90kSrI1d4ydxJRCPhUfjovcKpqp4wlLLHTNR3WHMlDSX5p2DEJhheu32phiRq4nNps7WG2IFQlk3G667QrW0AB7l0FWrYbjkQ-Lu6zbuYZNQf--7Wc1vjDO2gENvjQSGON9u6J3P4eTvMTyh7EeIBpcUVcgGjuIcM2f-rnxqQInp52MZQQIDAQABAoICAQDX-uGOO6Jd7g4vPRIvNh4hfn1eLTmyYajGIJMm7UxKl5E1_ScP4KQY2CpHIY59taX468QodwSv-G-VePLn88zz3tbQihy1-Dk7krYg_fMT-LIbkd-YcdbLg8JK3GZMUojGovOjKQGy6ifo9_RQqMZugj12Z3KOVcUnN7zRyh8mICazBpSmhivpYUEgrCwCGuDpCEuR1WuQE86JxwHPJ43eky7lGxXDvsMcPgJii5_JqO0zjdWrakBAMCHedBxdQG609KGUL8u2-h-t_mC4oYkfB_B11HrKZ7Hk5Y1AipSeoj6in9se2VnJJDfQT90VUxo25O8k6KDcVNP0ZJPd7oYQLLeqf4EeIvKwK7lYZ7lqFYa54L2Jt4FWagHjjxUWkVNBH7UwaCTS3xU1FTeBsL7evMlTdsJFsbBhAoqoblxx9JOj0BObCQSVbvvwplDGK6AImW2oV4kmNgMbw7kiVaUv7CO1vZlG5E4aKa1C4w1DPcn9w3AI8yrzV428VcqX6rgaMHIsLMCKGwN0G6Yke7aAGbJPgj9EXDzAfnK9ie-3oSWpjs1joFiqljPVUv9NQxeDxXFpMtIq2LR4ahcdly_M_7Pu_51kdEDqAUOn9UoMxMmgaAtsXmGNo-YNQQ1dja-GAgvp2fi_SUV8PaZ_G-4pLNdRFW2NZW_WQRWt6ydK0QKCAQEA73per7eE3HDr2Jn53A1qxgx557XWUelVZoxG9mTleCj1npkJWXo9BTH69-UHjrPhOJVAXJQftzH8wG9TRZcIsoYaqNgIdmlts2_ouEzUe6mNA3nhqaSPSf5mcgf7UEmGRa_SkCVPLOxunrZIon15hyn6goz3o1QSbT-HlotECPVqrwgCkvNS_kHWsG4UUT3q-PoyYBu1-5sCT2-_zaB66ARAW6pDdUyokcQRW-_PnrpiZCQKpaK-NkTb0yOokL7WjLiYWlD_lHetk6Conhg4go4UlBlQdPvYNe-hBulwBXcH4Ggu42YVMYb75FvDXPxc9E-hUFJv8C-tf0CSkMOZ1QKCAQEA-0luN3DXjlSFLx8BqrHmMGxZXcv0sgHIk-fEdffGI3N3_rqoSqu3aS78PBhlaAANjdYlMOXciOjE2uAzWGRv1RTSyW-b3PEC0eNF8dVe9bFXCwWS-b6O_M6WHN6IVQzeZVm5yksPAx4BDXvoN5bs61NwiZmWt0wJ-QfFvmwLfQu1WfetqqVsVRrtyLISshNYyqQZ6FSKx9EZ2a_luqTO2HR0Bei9Hmur0RwA2yUn5snddQj11nWR6Kag-QSlEBYVnylLW3xLejcYfdxfgqKeaGTaJvNL4sW35DamqQ_p__NLIVxSWp-0hMFzZfd10B3gUvAN62-Bgjncvj4kk7TrvQKCAQAiCa-ZpCkDOB2djM0hxNpvSeit0X-j5tlXmQqhDNg8yv2WTEQy7pfrvB3izC_VzaVuaHBceEVFwZoeM_SPCJeY4Ey7wPD6-6M3BOn8ABeXeBLt8o3rkdM3_ivLe2zyDXFDSGlSSatGRFi4wEn0pob2ejX8BlNQaKux0XzRHfxOlatTM31CK8mZD_yW2R6UKYvTVaSBWo70MyUR611EudGeVrRbEwlBi-LNzSN2gNBuzCkd-K12u3nztrfT-9aCtE1EdRxagfbBwHzwZb5xshmeHNm57xsrdXxWtjeaBuYAMNnywHwhoCnU_02gOJa9CbWgmAzioMT-S5iKZMAwSUz9AoIBAA0xmNDeYuL9OxTzStIcjxqBxdtv5wQlpdNmOuF6xfN8j5NXV5i8FWA3cFTzbveb8Ro-YSuFFiQ2HIfld6yvcVO9ySd8bbGXEe_VQAnnixnZWtmgTExCnh1V93nCkWPtzguCP4gIktw2ChYcKGAq03uzoNgIsWokWu2xY8eQwrWpFLeJkpvAHcUGKe_8sZCaBXJ2VUnmjnbZWsMcQjKfjqC81I6u3qcnPhk3oC_hbovmk3MeqlG9UJDnltIcVVJX5oC52VQPXaMoG2gYVwdz5F9U1ENxSM26VeJsoCmGRWID8zDoOQa7Fe5WfemfqZboyqtwITr4WtNsmFOAzcjXmf0CggEBANCwmckvsSJrVAhc3tTCDT5sKQA7lyqEx7AXpDIUA9D0NaaetL7Yh_YMHnADnrvNsc5_kvgaTdNk8sgzsp0J3dyPD-xBnROGyg_Jt7h7gTPzh2q6y6NRSVbBBnzAp2NSNbIkZm5tg8G-soU9UB50vg0sBUILBpWUX9LlZMVXzbxBo5i2omvVTP1gRRJzxj0itf3TSEJnBvY9KInrpI8RzfzoHrrC_V4_ftZH7yAmVyH3gw03yagoRrnZagUydf7cXbP1YoOBizTgt_WBiQk47Ym4JvEWDTHmEsT4snYjujiMvAlAS37JyvWDosQZlO5eDVv0XR3aNy5pOR_ouC0o8a8' }
  let(:public_key_base64_url) { 'MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA6xGr1bqTn_hu1PN6IdEyiytFPvQXWOHIDwnuuoMi6HWPTRe_q_TYGR5bEjml10whCTqPP62_iRVt-K5pkSAqepoXgf3R8LltVU4ESu11tYW_A4QPBqJTMHS3zx62iLiaE67XYMcxF0jTh9HnJhOCnRw7z9f4-_VRd0TrjYeptsdjHl-YqS9bym_ZTZtfGfnMFvIjfdNKFD4dtQ3G8kuAVH0rHXDq4M86GZ-3WpgEAHZSLqav1geOwJDlxoDoKwLI1ca1wJDjbe24vOzmvxyJ75Xh0Fhus9rK8L0_t3Ptwg1C6JKLuNmbprp6-qvs4_8heLURlDmoLZDGdkkeA1W0Ys99wTU_D-eB7eWAMUPHKvesoF8AF58-pzUg7EtPUtgNiy_24888zVSRk8Skp8QtTf4xv5KlJu4s696tbEEKjU-QucpQ5_-QfoGUvOFdoj_j92tsKnfzz3kC8d15mNexk3x8nws8HZtLvpUhLLvLCekoKYsQQkrgsT6LgvdJEqyNXeMncSUQj4VH46L3CqaqeMJSyx0zUd1hzJQ0l-adgxCYYXrt9qYYkauJzabO1htiBUJZNxuuu0K1tAAe5dBVq2G45EPi7us27mGTUH_vu1nNb4wztoBDb40Ehjjfbuidz-Hk7zE8oexHiAaXFFXIBo7iHDNn_q58akCJ6edjGUECAwEAAQ' }

  before do
    @e = Encryption.new
  end

  after do
    # Do nothing
  end

  context 'when any key is not passed and new key is generated' do
    it 'succeeds to generate a new key pair' do
      @e.generate_key_pair
      expect(@e.export_private_key).not_to be nil
    end
  end

  context 'when any key is not passed and new key is not generated' do
    it 'should raise an error in export_private_key' do
      expect { @e.export_private_key }.to raise_error 'Please pass private key'
    end

    it 'should raise an error in export_public_key' do
      expect { @e.export_public_key }.to raise_error 'Please pass public key'
    end

    it 'should raise an error in encrypt' do
      expect { @e.encrypt(message) }.to raise_error 'Please pass public key'
    end

    it 'should raise an error in decrypt' do
      expect { @e.decrypt(cipher) }.to raise_error 'Please pass private key'
    end

  end

  context 'when an existing key is passed' do
    it 'succeeds to decrypt cipher text' do
      @e.import_private_key(private_key_pem)
      plain_text = @e.decrypt(cipher)
      expect(plain_text).to eq message
    end

    it 'succeeds to export private key' do
      @e.import_private_key(private_key_pem)
      key = @e.export_private_key
      expect(key).to eq private_key_pem
    end

    it 'succeeds to import private key in Base64 URL' do
      @e.import_private_key_base64_url(private_key_base64_url)
      key = @e.export_private_key
      expect(key).to eq private_key_pem
    end

    it 'succeeds to import public key in Base64 URL' do
      @e.import_public_key_base64_url(public_key_base64_url)
      key = @e.export_public_key
      expect(key).to eq public_key_pem
    end

    it 'succeeds to export private key in Base64 URL' do
      @e.import_private_key(private_key_pem)
      key = @e.export_private_key(true)
      expect(key).to eq private_key_base64_url
    end

    it 'succeeds to export public key' do
      @e.import_private_key(private_key_pem)
      key = @e.export_public_key
      expect(key).to eq public_key_pem
    end

    it 'succeeds to export public key in Base64 URL' do
      @e.import_private_key(private_key_pem)
      key = @e.export_public_key(true)
      expect(key).to eq public_key_base64_url
    end
  end
end