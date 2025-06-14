#
# Author:: Thijs Houtenbos <thoutenbos@schubergphilis.com>
# Cookbook:: acme
# Resource:: certificate
#
# Copyright 2015-2016 Schuberg Philis
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

actions :create
default_action :create

attribute :cn,                    :kind_of => String, :required => true
attribute :alt_names,             :kind_of => Array,  :default => []

attribute :path,                  :kind_of => String, :name_attribute => true
attribute :key,                   :kind_of => String, :required => true

attribute :owner,                 :kind_of => [Integer, String]
attribute :group,                 :kind_of => [Integer, String]

attribute :key_owner,             :kind_of => [Integer, String], default: 'root'
attribute :key_group,             :kind_of => [Integer, String], default: 'root'

attribute :min_validity,          :kind_of => Integer
attribute :allow_extra_alt_names, :kind_of => [TrueClass, FalseClass], :default => false

def webserver(server)
	sym = server.to_sym.capitalize

	raise "Unknown server: #{sym}. Available: #{Chef::Provider::SSLCertificate.constants}" unless Chef::Provider::SSLCertificate.const_defined?(sym)
	provider(Chef::Provider::SSLCertificate.const_get(sym))
end

def min_expiry
	distribution = rand * 0.25 + 1.0

	@min_expiry = Time.now + (distribution * 3600 * 24 * (@min_validity || node[:acme][:renew])).to_i
end

def after_created
end
