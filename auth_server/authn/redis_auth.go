/*
   Copyright 2015 Cesanta Software Ltd.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       https://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package authn

import (
	"fmt"

	"github.com/mediocregopher/radix.v2/pool"

	"golang.org/x/crypto/bcrypt"
)

type RedisAuthConfig struct {
	Address   string `yaml:"address,omitempty" json:"address,omitempty"`
	KeyPrefix string `yaml:"key_prefix,omitempty" json:"key_prefix,omitempty"`
}

type redisAuth struct {
	pool *pool.Pool
	conf *RedisAuthConfig
}

func NewRedisAuth(c *RedisAuthConfig) *redisAuth {
	return &redisAuth{conf: c}
}

func (ra *redisAuth) Connect() error {
	var err error
	ra.pool, err = pool.New("tcp", ra.conf.Address, 10)

	if err != nil {
		return err
	}

	return nil
}

func (ra *redisAuth) Authenticate(user string, password PasswordString) (bool, error) {
	client, err := ra.pool.Get()
	if err != nil {
		return false, err
	}
	defer ra.pool.Put(client)

	pass, err := client.Cmd("GET", ra.keyName("user", user)).Bytes()
	if err != nil {
		return false, NoMatch
	}

	if pass != nil {
		if bcrypt.CompareHashAndPassword(pass, []byte(password)) != nil {
			return false, nil
		}
	}

	return true, nil
}

func (ra *redisAuth) Stop() {
	ra.pool.Empty()
}

func (ra *redisAuth) Name() string {
	return "redis"
}

func (ra *redisAuth) keyName(key string, user string) string {
	return fmt.Sprintf("%s%s:%s", ra.conf.KeyPrefix, key, user)
}
