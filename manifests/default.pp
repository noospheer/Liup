$basedir   = '/home/vagrant'
$mainuser  = 'vagrant'
$maingroup = 'vagrant'

package { 'cmake':
  ensure => installed,
}

package { 'python-numpy':
  ensure => installed,
}

package { 'ipython':
  ensure => installed,
}