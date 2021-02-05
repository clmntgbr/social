<?php

namespace App\Traits;

use App\Entity\User\User;
use DateTimeImmutable;
use Doctrine\ORM\Mapping as ORM;
use Gedmo\Mapping\Annotation as Gedmo;

trait DoctrineEventsTrait
{
    /**
     * @var \DateTime|null
     *
     * @Gedmo\Timestampable(on="create")
     * @ORM\Column(type="datetime")
     */
    public $createdAt;

    /**
     * @var \DateTime|null
     *
     * @Gedmo\Timestampable(on="update")
     * @ORM\Column(type="datetime", nullable=true)
     */
    public $updatedAt;

    /**
     * @var User|null
     *
     * @Gedmo\Blameable(on="create")
     * @ORM\ManyToOne(targetEntity="App\Entity\User\User")
     * @ORM\JoinColumn(name="created_by", referencedColumnName="id", nullable=true))
     */
    public $createdBy;

    public function getCreatedAt(): ?\DateTimeImmutable
    {
        if ($this->createdAt) {
            return DateTimeImmutable::createFromMutable($this->createdAt);
        }
        return null;
    }

    public function getUpdatedAt(): ?\DateTimeImmutable
    {
        if ($this->updatedAt) {
            return DateTimeImmutable::createFromMutable($this->updatedAt);
        }
        return null;
    }

    public function getCreatedBy(): ?User
    {
        return $this->createdBy;
    }
}