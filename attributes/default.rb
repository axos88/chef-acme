#
# Author:: Thijs Houtenbos <thoutenbos@schubergphilis.com>
# Cookbook:: acme
# Attribute:: default
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

# :staging or :prod
env = :prod

default['acme']['contact']     = []

if env == :staging
  Chef::Log.warn("Using staging ACME endpoint. Issued certificates will NOT be valid!")
  default['acme']['endpoint']  = 'https://acme-staging-v02.api.letsencrypt.org'
  default['acme']['issuer']    = 'http://cert.stg-int-x1.letsencrypt.org/'
elsif env == :prod
  default['acme']['endpoint']  = 'https://acme-v02.api.letsencrypt.org'
  default['acme']['issuer']    = 'http://r3.i.lencr.org/'
else
  fail "Unknown acme environment: #{env}. Should be :staging or :prod"
end

default['acme']['renew']       = 30
default['acme']['source_ips']  = ['66.133.109.36']

default['acme']['private_key'] = nil
default['acme']['gem_deps']    = true
default['acme']['key_size']    = 2048

default['acme']['dns_servers'] = [
{ provider: "DigitalOcean", location: "NS1", address: "ns1.digitalocean.com" },
{ provider: "DigitalOcean", location: "NS2", address: "ns2.digitalocean.com" },
{ provider: "DigitalOcean", location: "NS3", address: "ns3.digitalocean.com" },
{ lat: 38, lng: -122, location: "Holtsville NY, United States", flag: "us", provider: "OpenDNS", address: "208.67.222.220" },
{ lat: 37.4059, lng: -122.078, location: "Mountain View CA, United States", flag: "us", provider: "Google", address: "8.8.8.8" },
{ lat: 37.8793, lng: -122.265, location: "Berkeley, US", flag: "us", provider: "Quad9", address: "9.9.9.9" },
{ lat: 40.7142, lng: -74.0059, location: "Brooklyn, United States", flag: "us", provider: "Verizon Fios Business", address: "98.113.146.9" },
{ lat: 26, lng: -80, location: "Miami, United States", flag: "us", provider: "AT&amp;T Services", address: "12.121.117.201" },
{ lat: 38.9977, lng: -77.4331, location: "Ashburn, United States", flag: "us", provider: "NeuStar", address: "156.154.70.64" },
{ lat: 37.2799, lng: -121.956, location: "San Jose, United States", flag: "us", provider: "Corporate West Computer Systems", address: "66.206.166.2" },
{ lat: 49, lng: -123, location: "Burnaby, Canada", flag: "ca", provider: "Fortinet Inc", address: "208.91.112.53" },
# { lat: 57, lng: 61, location: "Yekaterinburg, Russian Federation", flag: "ru", provider: "Skydns", address: "195.46.39.39" },
{ lat: -26, lng: 29, location: "Cullinan, South Africa", flag: "za", provider: "Liquid Telecommunications Ltd", address: "5.11.11.5" },
{ lat: 51.5308, lng: 4.4652, location: "Roosendaal, Netherlands", flag: "nl", provider: "NForce Entertainment B.V.", address: "185.107.80.84" },
{ lat: 48.8534, lng: 2.3488, location: "Paris, France", flag: "fr", provider: "Online S.A.S.", address: "163.172.107.158" },
{ lat: 41.656, lng: -0.8773, location: "Zaragoza, Spain", flag: "es", provider: "Diputacion Provincial de Zaragoza", address: "195.235.225.10" },
{ lat: 46.9357, lng: 9.5649, location: "Zizers, Switzerland", flag: "ch", provider: "Oskar Emmenegger", address: "194.209.157.109" },
{ lat: 47.2626, lng: 11.3945, location: "Innsbruck, Austria", flag: "at", provider: "nemox.net", address: "83.137.41.9" },
{ lat: 55, lng: -1, location: "Guisborough, United Kingdom", flag: "gb", provider: "Onyx Internet Ltd", address: "195.97.240.237" },
{ lat: 55.6666, lng: 12.4, location: "Glostrup, Denmark", flag: "dk", provider: "Sentia Denmark A/S", address: "86.58.175.11" },
{ lat: 49.5064, lng: 8.2118, location: "Frankfurt am Main, Germany", flag: "de", provider: "DNS.WATCH", address: "84.200.70.40" },
{ lat: 25.65, lng: -100.083, location: "Juarez, Mexico", flag: "mx", provider: "IP Matrix S.A. de C.V.", address: "201.174.34.194" },
{ lat: -29.7175, lng: -52.4258, location: "Santa Cruz do Sul, Brazil", flag: "br", provider: "Claro S.A", address: "200.248.178.54" },
{ lat: 3.1412, lng: 101.687, location: "Kuala Lumpur, Malaysia", flag: "my", provider: "Ohana Communications Sdn Bhd", address: "103.26.250.4" },
{ lat: -38, lng: 145, location: "Research, Australia", flag: "au", provider: "Cloudflare Inc", address: "1.1.1.1" },
{ lat: -33.8678, lng: 151.207, location: "Melbourne, Australia", flag: "au", provider: "Pacific Internet", address: "61.8.0.113" },
{ lat: -36.8666, lng: 174.767, location: "Auckland, New Zealand", flag: "nz", provider: "ICONZ Ltd", address: "210.48.77.68" },
{ lat: 1.2896, lng: 103.85, location: "Singapore", flag: "sg", provider: "Dirft South Celtic Way Daventry", address: "210.16.120.48" },
{ lat: 37.5682, lng: 126.978, location: "Seoul, South Korea", flag: "kr", provider: "LG Dacom Corporation", address: "164.124.101.2" },
{ lat: 30.2936, lng: 120.161, location: "Hangzhou, China", flag: "cn", provider: "Aliyun Computing Co. Ltd", address: "223.5.5.5" },
{ lat: 36.9081, lng: 30.6955, location: "Antalya, Turkey", flag: "tr", provider: "Teknet Yazlim", address: "31.7.37.37" },
{ lat: 11.1333, lng: 79.0833, location: "Ariyalur, India", flag: "in", provider: "Railwire", address: "112.133.219.34" },
{ lat: 34, lng: 73, location: "Islamabad, Pakistan", flag: "pk", provider: "Multinet Pakistan Pvt. Ltd", address: "125.209.116.22" },
{ lat: 41.6932, lng: -8.8328, location: "Viana do Castelo, Portugal", flag: "pt", provider: "CLOUDITY Network", address: "185.83.212.30" },
{ lat: 53, lng: -6, location: "Ireland", flag: "ie", provider: "Daniel Cid", address: "185.228.168.9" },
{ lat: 24.1333, lng: 89.0833, location: "Pabna, Bangladesh", flag: "bd", provider: "Pabna Cable Vision", address: "103.153.154.2" }

]