#!/usr/bin/env ruby
# encoding: ASCII-8BIT

require 'base64'
require 'digest'
require 'json'
require 'openssl'
require 'securerandom'
require 'zlib'

Dir.chdir(File.dirname(__FILE__))

SIZE = 1024
L = SIZE / 4 - 1
CAFE = "\xCA\xFE\x12\x04"

class String
  def enhex
    self.unpack('H*')[0]
  end
end

def gg(msg)
  puts "\e[1;31mMEOW! #{msg}\e[0m"
  exit 1
end

def gen_key
  e = 3.to_bn
  p = OpenSSL::BN::generate_prime(SIZE, false)
  q = OpenSSL::BN::generate_prime(SIZE, false)
  n = p * q
  phi = (p - 1) * (q - 1)
  d = e.mod_inverse(phi)
  [e, d, n]
end

def H(m)
  Digest::SHA256.hexdigest(m).to_i(16).to_bn
end

def unpad(s)
  gg 'meow zzz' unless s.size == L && s[0, 4] == CAFE
  s[4..-1].gsub(/^\x00*/, '')
end

def pad(s)
  zero = L - 4 - s.size
  gg 'meooooooooooooooooow' unless zero >= 0
  CAFE + "\x00" * zero + s
end

def sign(m, d, n)
  h = H(m)
  nonce = SecureRandom.base64(6)
  obj = {hash: h.to_i, nonce: nonce}
  num = pad(Zlib.deflate(obj.to_json)).enhex.to_i(16).to_bn
  gg 'meow??' if num >= n
  num.mod_exp(d, n)
rescue
  gg 'meeeeeow'
end

def verify(m, sig, e, n)
  num = sig.mod_exp(e, n)
  obj = JSON[Zlib.inflate(unpad(num.to_s(2)))]
  gg 'meow T_T' if obj['hash'] != H(m)
  gg 'meowwww' unless obj['nonce'] && Base64::decode64(obj['nonce']).size == 6
  true
rescue
  false
end

def decrypt(m, d, n)
  gg 'meow :(' unless m >= 0 && m < n
  c = m.mod_exp(d, n).to_s(2)
  unpad(c)
rescue
  nil
end

FLAG = IO.read('flag')

# CATS ARE TRUE COLOR!!!
CATS = Dir.glob('cat/cat*')

$stdout.sync = true

def main
  e, d, n = gen_key
  loop do
    puts 'meow?'
    cmd = gets.strip
    case cmd
    when 'meow~'
      puts 'meow~'
      msg = gets.strip
      gg 'meow :O' if msg.size > 128
      gg 'meow?!' if msg.include?('meow')
      puts sign(msg, d, n)
    when 'meow!'
      puts 'meow meow~'
      admin_cmd = decrypt(gets.strip.to_i(16).to_bn, d, n)
      gg 'meow?' if admin_cmd.nil?
      case admin_cmd
      when /^meow(.)$/
        # meow? meow!
        meow = $1
        puts 'meow meow meow?'
        sig = gets.strip.to_i(16).to_bn
        if verify(admin_cmd, sig, e, n)
          system(meow)
        else
          gg 'meow!?'
        end
      when 'meow'
        puts IO.read(CATS.sample)
      else
        puts 'meow...!'
      end
    when 'meow.'
      break
    else
      puts 'meow...?'
    end
  end
end

main
