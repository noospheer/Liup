$basedir   = '/home/vagrant'
$mainuser  = 'vagrant'
$maingroup = 'vagrant'

package { 'python-numpy':
  ensure => installed,
}

package { 'ipython':
  ensure => installed,
}

package { 'libxml2-utils':
  ensure => installed,
}