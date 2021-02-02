#
# Author:: Thijs Houtenbos <thoutenbos@schubergphilis.com>
# Cookbook:: acme
# Library:: acme
#
# Copyright 2015-2017 Schuberg Philis
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

begin
  require 'acme-client'
rescue LoadError => e
  Chef::Log.warn("Acme library dependency 'acme-client' not loaded: #{e}")
end

def acme_client
  Chef::Application.fatal!('Acme requires that a contact is specified') if node['acme']['contact'].empty?
  return @acme_client if @acme_client

  private_key = OpenSSL::PKey::RSA.new(node['acme']['private_key'].nil? ? 2048 : node['acme']['private_key'])
  kid = !node['acme']['private_key'].nil? && node['acme']['kid']

  @acme_client = Acme::Client.new(private_key: private_key, directory: "#{node['acme']['endpoint']}/directory", kid: kid)

  if node['acme']['private_key'].nil? || kid.nil?
    Chef::Log.warn("Could not find acme account. Registering a new one!")

    kid = acme_client.new_account(contact: node['acme']['contact'], terms_of_service_agreed: true).kid
    node.normal['acme']['private_key'] = private_key.to_pem
    node.normal['acme']['kid'] = kid
    node.save
  end

  @acme_client
end

def acme_csr(cn, key, alt_names = [])
  Acme::Client::CertificateRequest.new(
    common_name: cn,
    names: [cn, alt_names].flatten.compact.sort.uniq,
    private_key: key
  )
end

def self_signed_cert(cn, alts, key)
  cert = OpenSSL::X509::Certificate.new
  cert.subject = cert.issuer = OpenSSL::X509::Name.new([['CN', cn, OpenSSL::ASN1::UTF8STRING]])
  cert.not_before = Time.now
  cert.not_after = Time.now + 60 * 60 * 24 * node['acme']['renew']
  cert.public_key = key.public_key
  cert.serial = 0x0
  cert.version = 2

  ef = OpenSSL::X509::ExtensionFactory.new
  ef.subject_certificate = cert
  ef.issuer_certificate = cert

  cert.extensions = []

  cert.extensions += [ef.create_extension('basicConstraints', 'CA:FALSE', true)]
  cert.extensions += [ef.create_extension('subjectKeyIdentifier', 'hash')]
  cert.extensions += [ef.create_extension('subjectAltName', alts.map { |d| "DNS:#{d}"}.join(','))] if alts.length > 0

  cert.sign key, OpenSSL::Digest::SHA256.new
end
